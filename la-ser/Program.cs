using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace la_ser
{

    class StatusFile
    {
        string name;

        public string Name
        {
            get { return name; }
            set { name = value; }
        }
        int ssn;

        public int Ssn
        {
            get { return ssn; }
            set { ssn = value; }
        }
        string status;

        public string Status
        {
            get { return status; }
            set { status = value; }
        }

        public static List<StatusFile> GetStatusFile()
        {
            string line;
            List<StatusFile> statusFile = new List<StatusFile>();
            System.IO.StreamReader sfile = new System.IO.StreamReader("Status.txt");
            while ((line = sfile.ReadLine()) != null)
            {
                StatusFile obj = new StatusFile();
                string[] arr = line.Split(',');
                obj.Name = arr[0];
                obj.Ssn = Convert.ToInt32(arr[1]);
                obj.Status = arr[2];
                statusFile.Add(obj);
            }
            sfile.Close();
            return statusFile;
        }
    }

    class VerifyFile
    {
        int ssn;

        public int Ssn
        {
            get { return ssn; }
            set { ssn = value; }
        }
        int valno;

        public int Valno
        {
            get { return valno; }
            set { valno = value; }
        }

        public static List<VerifyFile> GetVerifyFile()
        {
            string line;
            List<VerifyFile> verifyFile = new List<VerifyFile>();
            System.IO.StreamReader vfile = new System.IO.StreamReader("Verify.txt");
            while ((line = vfile.ReadLine()) != null)
            {
                VerifyFile obj = new VerifyFile();
                string[] arr = line.Split(',');
                obj.Ssn = Convert.ToInt32(arr[0]);
                obj.Valno = Convert.ToInt32(arr[1]);
                verifyFile.Add(obj);
            }

            vfile.Close();
            return verifyFile;
        }
    }

    class Program
    {

        
        static int counter = 1;

        public static string GenerateKeys(int counter)
        {
            string publicKey, privateKey = string.Empty ;
            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;
            StreamWriter publicKeyFile = null,privateKeyFile;
            try
            {

                cspParams = new CspParameters();
                cspParams.ProviderType = 1;

                cspParams.Flags = CspProviderFlags.UseArchivableKey;
                cspParams.KeyNumber = (int)KeyNumber.Exchange;
                rsaProvider = new RSACryptoServiceProvider(cspParams);

                publicKey = rsaProvider.ToXmlString(false);


                publicKeyFile = File.CreateText(@"c:\LAPublicKey"+counter.ToString()+".xml");
                publicKeyFile.Write(publicKey);
                publicKeyFile.Close();

                privateKey = rsaProvider.ToXmlString(true);

                privateKeyFile = File.CreateText(@"c:\LAPrivateKey" + counter.ToString() + ".xml");
                privateKeyFile.Write(privateKey);
                privateKeyFile.Close();
                
            }
            catch (Exception ex)
            {

                Console.WriteLine("Exception generating a new key pair! More info:");
                Console.WriteLine(ex.Message);
            }
            return privateKey; 
        }

        public static string Decrypt(byte[] encryptedBytes, string privateKey)
        {
            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;

            string plainText = "";

            byte[] plainBytes = null;

            try
            {
                cspParams = new CspParameters();
                cspParams.ProviderType = 1;

                rsaProvider = new RSACryptoServiceProvider(cspParams);
                rsaProvider.FromXmlString(privateKey);
                plainBytes = rsaProvider.Decrypt(encryptedBytes, false);
                plainText = Encoding.Unicode.GetString(plainBytes);
                return plainText;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return plainText;
            }


        }

        public static void GenerateKeyForVF(int counter)
        {
            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;
            StreamWriter sw = null;
            cspParams = new CspParameters();
            cspParams.ProviderType = 1;
            cspParams.Flags = CspProviderFlags.UseArchivableKey;
            cspParams.KeyNumber = (int)KeyNumber.Exchange;
            rsaProvider = new RSACryptoServiceProvider(cspParams);
            string dspv = rsaProvider.ToXmlString(true);
            sw = File.CreateText(@"c:\LADigitalSignatureKeyPrivate"+counter+".xml");
            sw.Write(dspv);
            sw.Close();
            string dspu = rsaProvider.ToXmlString(false);
            sw = File.CreateText(@"c:\LADigitalSignatureKeyPublic"+counter+".xml");
            sw.Write(dspu);
            sw.Close();
        }

        public static byte[] EncryptForSignature(string toencrypt,int counter)
        {
            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;
            StreamReader sw = null;

            string publicKeyText = "";

            byte[] plainBytes = null;
            byte[] encryptedBytes = null;


            cspParams = new CspParameters();
            cspParams.ProviderType = 1;

            rsaProvider = new RSACryptoServiceProvider(cspParams);

            sw = File.OpenText(@"c:\VFDigitalSignatureKeyPublic"+counter+".xml");
            publicKeyText = sw.ReadToEnd();
            sw.Close();
            rsaProvider.FromXmlString(publicKeyText);
            plainBytes = Encoding.Unicode.GetBytes(toencrypt);
            encryptedBytes = rsaProvider.Encrypt(plainBytes, false);
            return encryptedBytes;

        }

        public static byte[] CreateSignature(byte[] encrypted,int counter)
        {
            RSACryptoServiceProvider rsaCSP = new RSACryptoServiceProvider();
            SHA1Managed hash = new SHA1Managed();
            byte[] hashedData;

            StreamReader sr = File.OpenText(@"c:\LADigitalSignatureKeyPrivate"+counter+".xml");
            string privateKeyText = sr.ReadToEnd();
            sr.Close();

            rsaCSP.FromXmlString(privateKeyText);

            hashedData = hash.ComputeHash(encrypted);
            return rsaCSP.SignHash(hashedData, CryptoConfig.MapNameToOID("SHA1"));
        }

        static void Main(string[] args)
        {
            if (args.Length == 2)
            {

                Socket server = null;
                try
                {
                    

                    Int32 port = Convert.ToInt32(args[0]);

                    IPAddress[] addrs = Dns.GetHostEntry(Dns.GetHostName()).AddressList;

                    IPAddress add = null;
                    foreach (IPAddress ipv4 in addrs)
                    {
                        if (ipv4.AddressFamily == AddressFamily.InterNetwork)
                        {
                            add = ipv4;
                        }
                    }
                    IPAddress localAddr = IPAddress.Parse(add.ToString());
                    IPEndPoint localEndpoint = new IPEndPoint(localAddr, port);
                    server = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                    server.Bind(localEndpoint);


                    List<StatusFile> statusFile = StatusFile.GetStatusFile();
                    List<VerifyFile> verifyFile = VerifyFile.GetVerifyFile();


                    while (true)
                    {

                        server.Listen(10);
                        Socket client = server.Accept();
                        
                        byte[] type = System.Text.Encoding.ASCII.GetBytes("LA"+"$"+counter.ToString());
                        client.Send(type);
                        string privateKey=GenerateKeys(counter);
                        GenerateKeyForVF(counter);
                        int i;
                        try
                        {
                            byte[] iData = new byte[128];
                            string input, output = "";
                            while ((i = client.Receive(iData)) != 0)
                            {
                                input = Decrypt(iData,privateKey);
                                string[] arr = input.Split('$');
                                string name = arr[0];
                                if (!string.IsNullOrEmpty(name) && !string.IsNullOrEmpty(arr[1]))
                                {
                                    int ssn = Convert.ToInt32(arr[1]);
                                    Console.WriteLine(name);
                                    var contains = statusFile.Find(x => x.Ssn.Equals(ssn) && x.Name.Equals(name, StringComparison.OrdinalIgnoreCase));
                                    if (contains != null)
                                    {
                                        string status = statusFile.Find(x => x.Ssn.Equals(ssn) && x.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).Status;

                                        if (status.Equals("citizen"))
                                        {
                                            int valno = verifyFile.Find(x => x.Ssn.Equals(ssn)).Valno;
                                            bool sendToLA = false;
                                            if (valno.Equals(0))
                                            {
                                                Random rand = new Random();
                                                int valn = rand.Next(10000000, 99999999);

                                                while (true)
                                                {
                                                    var vnoPresent = verifyFile.Find(x => x.Valno.Equals(valn));
                                                    if (vnoPresent == null)
                                                    {
                                                        sendToLA = true;
                                                        verifyFile.Find(x => x.Ssn.Equals(ssn)).Valno = valn;
                                                        string path = "Verify.txt";
                                                        using (var stream = new FileStream(path, FileMode.Truncate))
                                                        {
                                                            using (var writer = new StreamWriter(stream))
                                                            {
                                                                foreach (VerifyFile v in verifyFile)
                                                                {
                                                                    writer.WriteLine(v.Ssn + "," + v.Valno);
                                                                }
                                                            }
                                                        }
                                                        break;
                                                    }
                                                    valn += 1;
                                                }

                                            }
                                            output = verifyFile.Find(x => x.Ssn.Equals(ssn)).Valno.ToString();
                                            byte[] oData = System.Text.Encoding.ASCII.GetBytes(output);
                                            if (sendToLA)
                                            {
                                               try
                                                {
                                                    Socket sla = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                                                    sla.Connect(localAddr, Convert.ToInt32(args[1]));
                                                    byte[] outByte = Encoding.ASCII.GetBytes("LA"+"$"+counter.ToString());
                                                    sla.Send(outByte);
                                                    byte[] buffer = new byte[256];
                                                    int k = sla.Receive(buffer);
                                                    string statusFromVF = System.Text.Encoding.ASCII.GetString(buffer, 0, k);
                                                    if (statusFromVF.StartsWith("VF"))
                                                    {
                                                        string[] array = statusFromVF.Split('$');
                                                        byte[] encrypt = EncryptForSignature(output,Convert.ToInt32(array[1]));
                                                        byte[] signature = CreateSignature(encrypt, counter);
                                                        sla.Send(encrypt);
                                                        sla.Send(signature);
                                                    }
                                                }
                                                catch (Exception ex)
                                                {
                                                    Console.WriteLine(ex.Message);
                                                }
                                            }
                                            client.Send(oData);
                                            break;
                                        }
                                        else
                                        {
                                            output = "no";
                                            byte[] oData = System.Text.Encoding.ASCII.GetBytes(output);
                                            client.Send(oData);
                                            break;
                                        }
                                    }
                                    else
                                    {
                                        output = "invalid";
                                        byte[] oData = System.Text.Encoding.ASCII.GetBytes(output);
                                        client.Send(oData);
                                        break;
                                    }


                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            continue;
                        }
                        counter++;
                        client.Close();
                    }
                }
                catch (SocketException e)
                {
                    Console.WriteLine("SocketException: {0}", e);
                }
                finally
                {

                    server.Close();
                }


                Console.Read();
            }

        }
    }
}
