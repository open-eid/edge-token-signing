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
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Windows.Forms;
using Windows.ApplicationModel;
using Windows.ApplicationModel.AppService;
using Windows.Data.Json;
using Windows.Foundation.Collections;

namespace HostBackend
{
    class Program
    {
        enum KEY_SPEC : uint
        {
            AT_KEYEXCHANGE = 1,
            AT_SIGNATURE = 2,
            CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF,
        }

        static private readonly uint CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 0x00000004;
        static private readonly uint CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040;
        static private readonly uint CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000;

        [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptAcquireCertificatePrivateKey(
            IntPtr pCertContext, uint dwFlags, IntPtr pvParameters, out IntPtr phKey, ref KEY_SPEC pdwKeySpec, ref bool pfFree);

        [DllImport("Crypt32.dll", SetLastError = true, CharSet = CharSet.Auto)]
        private static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);
   
        [DllImport("ncrypt.dll", CharSet = CharSet.Auto, SetLastError = true)]
        public static extern int NCryptFreeObject(IntPtr hObject);

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
                    PackageVersion version = Package.Current.Id.Version;
                    response.Add("version", JsonValue.CreateStringValue(
                        string.Format("{0}.{1}.{2}.{3}", version.Major, version.Minor, version.Build, version.Revision)));
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
                                if (!extensions.Any() || ((extensions[0].KeyUsages & X509KeyUsageFlags.NonRepudiation) > 0) != forSigning)
                                    continue;
                                IntPtr pKey;
                                KEY_SPEC dwSpec = 0;
                                bool keyFree = false;
                                CryptAcquireCertificatePrivateKey(x.Handle, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                                    IntPtr.Zero, out pKey, ref dwSpec, ref keyFree);
                                if (pKey == IntPtr.Zero)
                                    continue;
                                switch (dwSpec)
                                {
                                    case KEY_SPEC.AT_KEYEXCHANGE:
                                    case KEY_SPEC.AT_SIGNATURE:
                                        if (keyFree)
                                            CryptReleaseContext(pKey, 0);
                                        break;
                                    case KEY_SPEC.CERT_NCRYPT_KEY_SPEC:
                                        if (keyFree)
                                            NCryptFreeObject(pKey);
                                        break;
                                }
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
                        byte[] signature = null;
                        if (certs[0].PublicKey.Oid.Value.Equals("1.2.840.10045.2.1"))
                        {
                            using (ECDsa ecdsa = certs[0].GetECDsaPrivateKey())
                            {
                                if (ecdsa == null)
                                    throw new ArgumentException("Failed to find certificate token");
                                signature = ecdsa.SignHash(StringToByte(request.GetNamedString("hash")));
                            }
                        }
                        else
                        {
                            using (RSACryptoServiceProvider rsa = (RSACryptoServiceProvider)certs[0].PrivateKey)
                            {
                                if (rsa == null)
                                    throw new ArgumentException("Failed to find certificate token");
                                signature = rsa.SignHash(StringToByte(request.GetNamedString("hash")),
                                        CryptoConfig.MapNameToOID(request.GetNamedString("hashtype").Replace("-", "")));
                            }
                        }
                        if (signature == null)
                            throw new Exception("Failed to sign hash");
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
