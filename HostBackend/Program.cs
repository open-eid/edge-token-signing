/*
 * Edge token signing extension
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 */

using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Windows.ApplicationModel.AppService;
using Windows.Data.Json;
using Windows.Foundation.Collections;

namespace HostBackend
{
    class Program
    {
        static AppServiceConnection connection = null;

        [STAThread]
        static void Main(string[] args)
        {
            Thread appServiceThread = new Thread(new ThreadStart(ThreadProc));
            appServiceThread.Start();
            Application.Run();
        }

        static async void ThreadProc()
        {
            connection = new AppServiceConnection();
            connection.AppServiceName = "ee.ria.esteid";
            connection.PackageFamilyName = Windows.ApplicationModel.Package.Current.Id.FamilyName;
            connection.RequestReceived += RequestReceived;
            connection.ServiceClosed += ServiceClosed;

            AppServiceConnectionStatus status = await connection.OpenAsync();
            switch (status)
            {
                case AppServiceConnectionStatus.Success:
                    break;
                case AppServiceConnectionStatus.AppNotInstalled:
                case AppServiceConnectionStatus.AppUnavailable:
                case AppServiceConnectionStatus.AppServiceUnavailable:
                case AppServiceConnectionStatus.Unknown:
                    return;
            }
        }

        private static void ServiceClosed(AppServiceConnection sender, AppServiceClosedEventArgs args)
        {
            Application.Exit();
        }

        private static void RequestReceived(AppServiceConnection sender, AppServiceRequestReceivedEventArgs args)
        {
            string key = args.Request.Message.First().Key;
            string value = args.Request.Message.First().Value.ToString();
            JsonObject request = JsonValue.Parse(value).GetObject();
            JsonObject response = new JsonObject();
            response.Add("api", JsonValue.CreateNumberValue(1));
            response.Add("result", JsonValue.CreateStringValue("ok"));
            if (request.ContainsKey("nonce"))
                response.Add("nonce", request.GetNamedValue("nonce"));
            switch (request.GetNamedString("type"))
            {
                case "VERSION":
                    response.Add("version", JsonValue.CreateStringValue("1.0.0.0"));
                    args.Request.SendResponseAsync(new ValueSet { ["message"] = response.ToString() }).Completed += delegate { };
                    break;
                case "CERT":
                    try
                    {
                        String info = "By selecting a certificate I accept that my name and personal ID code will be sent to service provider.";
                        switch (request.GetNamedString("lang").ToString())
                        {
                            case "et":
                            case "est": info = "Sertifikaadi valikuga nõustun oma nime ja isikukoodi edastamisega teenusepakkujale."; break;
                            case "lt":
                            case "lit": info = "Pasirinkdama(s) sertifikatą, aš sutinku, kad mano vardas, pavardė ir asmens kodas būtų perduoti e. paslaugos teikėjui."; break;
                            case "lv":
                            case "lat": info = "Izvēloties sertifikātu, es apstiprinu, ka mans vārds un personas kods tiks nosūtīts pakalpojuma sniedzējam."; break;
                            case "ru":
                            case "rus": info = "Выбирая сертификат, я соглащаюсь с тем, что мое имя и личный код будут переданы представителю услуг."; break;
                            default: break;
                        }
                        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                        store.Open(OpenFlags.ReadOnly);
                        if (store.Certificates.Count > 0)
                        {
                            bool forSigning = request.GetNamedString("filter", "SIGN").ToString() != "AUTH";
                            X509Certificate2Collection list = new X509Certificate2Collection();
                            foreach(X509Certificate2 x in store.Certificates.Find(X509FindType.FindByTimeValid, DateTime.Now, false))
                            {
                                List<X509KeyUsageExtension> extensions = x.Extensions.OfType<X509KeyUsageExtension>().ToList();
                                if (extensions.Any() && ((extensions[0].KeyUsages & X509KeyUsageFlags.NonRepudiation) > 0) == forSigning)
                                    list.Add(x);
                            }
                            X509Certificate2Collection certs = X509Certificate2UI.SelectFromCollection(
                                list, "", info, X509SelectionFlag.SingleSelection);
                            if (certs.Count > 0)
                            {
                                response.Add("cert", JsonValue.CreateStringValue(ByteToString(certs[0].Export(X509ContentType.Cert), false)));
                            }
                            else
                            {
                                response["result"] = JsonValue.CreateStringValue("user_cancel");
                                response.Add("message", JsonValue.CreateStringValue("user_cancel"));
                            }
                        }
                        else
                        {
                            response["result"] = JsonValue.CreateStringValue("no_certificates");
                            response.Add("message", JsonValue.CreateStringValue("no_certificates"));
                        }
                    }
                    catch (Exception e)
                    {
                        response["result"] = JsonValue.CreateStringValue("technical_error");
                        response.Add("message", JsonValue.CreateStringValue(e.Message));
                    }
                    args.Request.SendResponseAsync(new ValueSet { ["message"] = response.ToString() }).Completed += delegate { };
                    break;
                case "SIGN":
                    try
                    {
                        String info = request.GetNamedString("info", "");
                        if (info.Length > 500)
                            throw new ArgumentException("Info parameter longer than 500 chars");
                        if (info.Length > 0 && MessageBox.Show(info, "", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.No)
                            throw new Exception("User cancelled");

                        X509Certificate2 cert = new X509Certificate2(StringToByte(request.GetNamedString("cert")));
                        if (cert == null)
                            throw new ArgumentException("Failed to parse certificate");
                        X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
                        store.Open(OpenFlags.ReadOnly);
                        X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, cert.Thumbprint, false);
                        if (certs.Count == 0)
                            throw new ArgumentException("Failed to find certificate");
                        RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)certs[0].PrivateKey;
                        if (rsa == null)
                            throw new ArgumentException("Failed to find certificate token");
                        byte[] signature = rsa.SignHash(StringToByte(request.GetNamedString("hash")),
                            CryptoConfig.MapNameToOID(request.GetNamedString("hashtype").Replace("-", "")));
                        response.Add("signature", JsonValue.CreateStringValue(ByteToString(signature, false)));
                    }
                    catch (Exception e)
                    {
                        if (e is ArgumentException || e is ArgumentNullException)
                            response["result"] = JsonValue.CreateStringValue("invalid_argument");
                        else if (e.Message.Contains("cancelled"))
                            response["result"] = JsonValue.CreateStringValue("user_cancel");
                        else
                            response["result"] = JsonValue.CreateStringValue("technical_error");
                        response.Add("message", JsonValue.CreateStringValue(e.Message));
                    }
                    args.Request.SendResponseAsync(new ValueSet { ["message"] = response.ToString() }).Completed += delegate { };
                    break;
                default:
                    Application.Exit();
                    break;
            }
        }

        private static string ByteToString(byte[] bytes, bool upperCase)
        {
            StringBuilder str = new StringBuilder(bytes.Length * 2);
            for (int i = 0; i < bytes.Length; i++)
                str.Append(bytes[i].ToString(upperCase ? "X2" : "x2"));
            return str.ToString();
        }

        private static byte[] StringToByte(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }
    }
}
