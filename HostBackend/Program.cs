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
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Windows.Forms;
using Windows.ApplicationModel;
using Windows.ApplicationModel.AppService;
using Windows.Data.Json;
using Windows.Foundation.Collections;

namespace HostBackend
{
    static class Program
    {
        [DllImport("Crypt32.dll", CharSet = CharSet.Unicode)]
        private static extern bool CryptAcquireCertificatePrivateKey(
            IntPtr pCertContext, uint dwFlags, IntPtr pvParameters, out IntPtr phKey, out uint pdwKeySpec, out bool pfFree);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern bool CryptReleaseContext(IntPtr hProv, uint dwFlags);

        [DllImport("Advapi32.dll", CharSet = CharSet.Unicode)]
        private static extern bool CryptGetProvParam(
            IntPtr hProv, uint dwParam, out uint pbOutput, ref uint pdwDataLen, uint dwFlags);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        static extern int NCryptFreeObject(IntPtr hObject);

        [DllImport("ncrypt.dll", CharSet = CharSet.Unicode)]
        static extern int NCryptGetProperty(
            IntPtr hObject, String pszProperty, out IntPtr pbOutput, uint cbOutput, out uint pcbResult, uint dwFlags);

        static AppServiceConnection connection;

        [STAThread]
        static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Thread appServiceThread = new Thread(new ThreadStart(ThreadProc));
            appServiceThread.Start();
            Application.Run();
        }

        static async void ThreadProc()
        {
            connection = new AppServiceConnection
            {
                AppServiceName = "ee.ria.esteid",
                PackageFamilyName = Package.Current.Id.FamilyName
            };
            connection.RequestReceived += RequestReceived;
            connection.ServiceClosed += delegate
            {
                Application.Exit();
            };

            if ((await connection.OpenAsync()) != AppServiceConnectionStatus.Success)
                Application.Exit();
        }

        private static async void RequestReceived(AppServiceConnection sender, AppServiceRequestReceivedEventArgs args)
        {
            string value = args.Request.Message.First().Value.ToString();
            JsonObject request = JsonValue.Parse(value).GetObject();
            JsonObject response = new JsonObject
            {
                ["api"] = JsonValue.CreateNumberValue(1),
                ["result"] = JsonValue.CreateStringValue("ok")
            };
            if (request.TryGetValue("nonce", out var nonce))
                response.Add("nonce", nonce);
            switch (request.GetNamedString("type"))
            {
                case "VERSION":
                    PackageVersion version = Package.Current.Id.Version;
                    response.Add("version", JsonValue.CreateStringValue(
                        string.Format("{0}.{1}.{2}.{3}", version.Major, version.Minor, version.Build, version.Revision)));
                    break;
                case "CERT":
                    try
                    {
                        if (request.GetNamedString("filter", "SIGN") == "AUTH")
                            throw new ArgumentException();
                        String info = "By selecting a certificate I accept that my name and personal ID code will be sent to service provider.";
                        switch (request.GetNamedString("lang"))
                        {
                            case "et":
                            case "est": info = "Sertifikaadi valikuga nõustun oma nime ja isikukoodi edastamisega teenusepakkujale."; break;
                            case "lt":
                            case "lit": info = "Pasirinkdama(s) sertifikatą, aš sutinku, kad mano vardas, pavardė ir asmens kodas būtų perduoti e. paslaugos teikėjui."; break;
                            case "lv":
                            case "lat": info = "Izvēloties sertifikātu, es apstiprinu, ka mans vārds un personas kods tiks nosūtīts pakalpojuma sniedzējam."; break;
                            case "ru":
                            case "rus": info = "Выбирая сертификат, я соглашаюсь с тем, что мое имя и личный код будут переданы представителю услуг."; break;
                            default: break;
                        }
                        X509Certificate2Collection list = new X509Certificate2Collection();
                        using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                        {
                            store.Open(OpenFlags.ReadOnly);
                            foreach (X509Certificate2 x in store.Certificates.Find(X509FindType.FindByTimeValid, DateTime.UtcNow, false))
                                if (isNonRepudiation(x) && HasHWToken(x))
                                {
                                    list.Add(x);
                                    break;
                                }
                        }
                        if (list.Count > 0)
                        {
                            X509Certificate2Collection certs = X509Certificate2UI.SelectFromCollection(
                                list, "", info, X509SelectionFlag.SingleSelection);
                            if (certs.Count > 0)
                            {
                                response.Add("cert", JsonValue.CreateStringValue(ByteToString(certs[0].Export(X509ContentType.Cert))));
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
                        if (e is ArgumentException || e is ArgumentNullException)
                            response["result"] = JsonValue.CreateStringValue("invalid_argument");
                        else
                            response["result"] = JsonValue.CreateStringValue("technical_error");
                        response.Add("message", JsonValue.CreateStringValue(e.Message));
                    }
                    break;
                case "SIGN":
                    try
                    {
                        String info = request.GetNamedString("info", "");
                        if (info.Length > 500)
                            throw new ArgumentException("Info parameter longer than 500 chars");
                        if (info.Length > 0 && MessageBox.Show(info, "", MessageBoxButtons.YesNo, MessageBoxIcon.Information) == DialogResult.No)
                            throw new Exception("User cancelled");

                        string thumbprint;
                        using (X509Certificate2 cert = new X509Certificate2(StringToByte(request.GetNamedString("cert"))))
                        {
                            if (!isNonRepudiation(cert))
                                throw new ArgumentException();
                            thumbprint = cert.Thumbprint;
                        }
                        byte[] signature;
                        using (X509Store store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
                        {
                            store.Open(OpenFlags.ReadOnly);
                            X509Certificate2Collection certs = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                            if (certs.Count == 0)
                                throw new ArgumentException("Failed to find certificate");
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
                        }
                        if (signature == null)
                            throw new Exception("Failed to sign hash");
                        response.Add("signature", JsonValue.CreateStringValue(ByteToString(signature)));
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
                    break;
                default:
                    Application.Exit();
                    return;
            }
            await args.Request.SendResponseAsync(new ValueSet { ["message"] = response.ToString() });
        }

        private static bool HasHWToken(X509Certificate2 cert)
        {
            const uint CERT_NCRYPT_KEY_SPEC = 0xFFFFFFFF;

            const uint CRYPT_ACQUIRE_COMPARE_KEY_FLAG = 0x00000004;
            const uint CRYPT_ACQUIRE_SILENT_FLAG = 0x00000040;
            const uint CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG = 0x00020000;

            const uint PP_IMPTYPE = 0x3;

            const uint CRYPT_IMPL_HARDWARE = 0x1;
            const uint CRYPT_IMPL_REMOVABLE = 0x8;

            const string NCRYPT_IMPL_TYPE_PROPERTY = "Impl Type";
            const string NCRYPT_PROVIDER_HANDLE_PROPERTY = "Provider Handle";

            CryptAcquireCertificatePrivateKey(cert.Handle, CRYPT_ACQUIRE_PREFER_NCRYPT_KEY_FLAG | CRYPT_ACQUIRE_COMPARE_KEY_FLAG | CRYPT_ACQUIRE_SILENT_FLAG,
                IntPtr.Zero, out var key, out var dwSpec, out var keyFree);
            if (key == IntPtr.Zero)
                return false;
            uint type = 0;
            switch (dwSpec)
            {
                default:
                    uint typesize = sizeof(uint);
                    CryptGetProvParam(key, PP_IMPTYPE, out type, ref typesize, 0);
                    if (keyFree)
                        CryptReleaseContext(key, 0);
                    break;
                case CERT_NCRYPT_KEY_SPEC:
                    NCryptGetProperty(key, NCRYPT_PROVIDER_HANDLE_PROPERTY, out var prov, (uint)IntPtr.Size, out _, 0);
                    if (prov != IntPtr.Zero)
                    {
                        NCryptGetProperty(prov, NCRYPT_IMPL_TYPE_PROPERTY, out var tmp, sizeof(uint), out _, 0);
                        type = (uint)(long)tmp;
                        NCryptFreeObject(prov);
                    }
                    if (keyFree)
                        NCryptFreeObject(key);
                    break;
            }
            return (type & (CRYPT_IMPL_HARDWARE | CRYPT_IMPL_REMOVABLE)) > 0;
        }

        private static string ByteToString(byte[] bytes)
        {
            var map = "0123456789abcdef";
            var str = new char[bytes.Length * 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                var b = bytes[i];
                str[i * 2] = map[b >> 4];
                str[i * 2 + 1] = map[b & 15];
            }
            return new string(str);
        }

        private static byte[] StringToByte(string hex)
        {
            if (hex.Length % 2 != 0) throw new ArgumentException();
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                var v = (parse(hex[i * 2]) << 4) | parse(hex[i * 2 + 1]);
                bytes[i] = checked((byte)v);
            }
            return bytes;

            uint parse(uint c)
            {
                if ((c - '0') <= 9) return c - '0';
                c |= 32; // lowercase
                if ((c - 'a') <= 5) return c - 'a' + 10;
                return ~0u;
            }
        }

        private static bool isNonRepudiation(X509Certificate2 x509)
        {
            foreach (var ext in x509.Extensions)
                if (ext is X509KeyUsageExtension keyExt && ((keyExt.KeyUsages & X509KeyUsageFlags.NonRepudiation) > 0))
                    return true;
            return false;
        }
    }
}
