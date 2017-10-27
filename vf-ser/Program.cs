using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.IO;
using System.Net;
using System.Net.Sockets;

using System.Threading;
using System.Security.Cryptography;


namespace vf_ser
{
    class Program
    {
        static void Main(string[] args)
        {
            if (args.Length == 1)
            {
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

                TcpListener serverSocket = new TcpListener(localAddr, Convert.ToInt32(args[0]));
                TcpClient clientSocket = default(TcpClient);


                serverSocket.Start();
         //       Console.WriteLine("VF Server Started");
                int counter = 1;
                while (true)
                {
                    clientSocket = serverSocket.AcceptTcpClient();
                    HandleClinet client = new HandleClinet();
                    client.startClient(clientSocket, counter);
                    counter++;
                }

            }
        }
    }
    public class HandleClinet
    {
        TcpClient clientSocket;
        int clientNo;
        string privateKey;

        public void startClient(TcpClient inClientSocket, int counter)
        {
            this.clientSocket = inClientSocket;
            this.clientNo = counter;

            this.privateKey = GenerateKeys(this.clientNo);
            GenerateKeyForLA(this.clientNo);

            Thread ctThread = new Thread(startInteraction);
            ctThread.Start();
        }

        public static void GenerateKeyForLA(int counter)
        {

            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;
            StreamWriter sw = null;
            cspParams = new CspParameters();
            cspParams.ProviderType = 1;
            cspParams.Flags = CspProviderFlags.UseArchivableKey;
            cspParams.KeyNumber = (int)KeyNumber.Exchange;
            rsaProvider = new RSACryptoServiceProvider(cspParams);
            string dspu = rsaProvider.ToXmlString(false);
            sw = File.CreateText(@"c:\VFDigitalSignatureKeyPublic" + counter + ".xml");
            sw.Write(dspu);
            sw.Close();

            string dspv = rsaProvider.ToXmlString(true);
            sw = File.CreateText(@"c:\VFDigitalSignatureKeyPrivate" + counter + ".xml");
            sw.Write(dspv);
            sw.Close();
        }

        public static string GenerateKeys(int counter)
        {
            string publicKey, privateKey = string.Empty;
            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;
            StreamWriter publicKeyFile = null, privateKeyFile = null;
            try
            {

                cspParams = new CspParameters();
                cspParams.ProviderType = 1;

                cspParams.Flags = CspProviderFlags.UseArchivableKey;
                cspParams.KeyNumber = (int)KeyNumber.Exchange;
                rsaProvider = new RSACryptoServiceProvider(cspParams);

                publicKey = rsaProvider.ToXmlString(false);


                publicKeyFile = File.CreateText(@"c:\VFPublicKey" + counter.ToString() + ".xml");
                publicKeyFile.Write(publicKey);
                publicKeyFile.Close();

                privateKey = rsaProvider.ToXmlString(true);

                privateKeyFile = File.CreateText(@"c:\VFPrivateKey" + counter.ToString() + ".xml");
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

        public static bool VerifySignatureAndDecrypt(byte[] data, byte[] signature, int counter)
        {
            RSACryptoServiceProvider rsaCSP = new RSACryptoServiceProvider();
            SHA1Managed hash = new SHA1Managed();
            byte[] hashedData;

            StreamReader sr = File.OpenText(@"c:\LADigitalSignatureKeyPublic" + counter + ".xml");
            string publicKeyText = sr.ReadToEnd();
            sr.Close();

            rsaCSP.FromXmlString(publicKeyText);
            bool dataOK = rsaCSP.VerifyData(data, CryptoConfig.MapNameToOID("SHA1"), signature);
            hashedData = hash.ComputeHash(data);
            return rsaCSP.VerifyHash(hashedData, CryptoConfig.MapNameToOID("SHA1"), signature);

        }

        public static string DecryptForSignature(byte[] encrypted, int counter)
        {
            CspParameters cspParams = new CspParameters();
            cspParams.ProviderType = 1;

            RSACryptoServiceProvider rsaProvider = new RSACryptoServiceProvider(cspParams);
            StreamReader sr = File.OpenText(@"c:\VFDigitalSignatureKeyPrivate" + counter + ".xml");
            string privateKey = sr.ReadToEnd();
            sr.Close();
            rsaProvider.FromXmlString(privateKey);
            byte[] plainBytes = rsaProvider.Decrypt(encrypted, false);
            string plainText = Encoding.Unicode.GetString(plainBytes);
            return plainText;
        }
        private void startInteraction()
        {
            byte[] type = System.Text.Encoding.ASCII.GetBytes("VF" + "$" + clientNo.ToString());
            byte[] clientType = new byte[4];
            NetworkStream networkStream = clientSocket.GetStream();
            networkStream.Write(type, 0, type.Length);
            networkStream.Read(clientType, 0, clientType.Length);
            string client = System.Text.Encoding.ASCII.GetString(clientType);

            while (true)
            {
                try
                {

                    if (client.StartsWith("LA"))
                    {
                        byte[] buffer = new byte[128];
                        int i = networkStream.Read(buffer, 0, buffer.Length);
                        byte[] data = buffer;
                        byte[] buffer2 = new byte[128];
                        string[] array = client.Split('$');
                        int j = networkStream.Read(buffer2, 0, buffer2.Length);
                        byte[] signature = buffer2;
                        if (VerifySignatureAndDecrypt(data, signature, Convert.ToInt32(array[1])))
                        {

                            string vno = DecryptForSignature(data, this.clientNo);
                            if (!File.Exists("Voternumber.txt"))
                            {
                                StreamWriter sw = File.CreateText("Voternumber.txt");
                                sw.WriteLine(vno + "," + "0");
                                sw.Close();
                            }
                            else
                            {
                                StreamWriter sw = File.AppendText("Voternumber.txt");
                                sw.WriteLine(vno + "," + "0");
                                sw.Close();
                            }
                    //        Console.WriteLine("Received V Number from LA Server: {0}", vno);
                            break;
                        }
                    }
                    if (client.StartsWith("VC"))
                    {

                        bool exit = false;
                        byte[] buffer = new byte[128];
                        int i = networkStream.Read(buffer, 0, buffer.Length);

                        string vno = Decrypt(buffer, this.privateKey);                       
                        string line;

                        Dictionary<int, int> voterfile = new Dictionary<int, int>();
                        System.IO.StreamReader sfile = new System.IO.StreamReader("Voternumber.txt");

                        while ((line = sfile.ReadLine()) != null)
                        {
                            string[] arr = line.Split(',');
                            voterfile.Add(Convert.ToInt32(arr[0]), Convert.ToInt32(arr[1]));
                        }
                        sfile.Close();

                        if (voterfile.ContainsKey(Convert.ToInt32(vno)))
                        {
                            byte[] msg = System.Text.Encoding.ASCII.GetBytes("valid");
                            networkStream.Write(msg, 0, msg.Length);
                            byte[] inD = new byte[256];
                            string state = "";
                            do
                            {
                                int k = networkStream.Read(inD, 0, inD.Length);
                                state = System.Text.Encoding.ASCII.GetString(inD, 0, k);
                                switch (Convert.ToInt32(state))
                                {
                                    case 1:
                                        if (voterfile[Convert.ToInt32(vno)] == 0)
                                        {
                                            byte[] status = System.Text.Encoding.ASCII.GetBytes("not voted");
                                            networkStream.Write(status, 0, status.Length);
                                            byte[] vote = new byte[1];
                                            networkStream.Read(vote, 0, 1);
                                            int v = Convert.ToInt32(System.Text.Encoding.ASCII.GetString(vote));
                                            voterfile.Clear();
                                            System.IO.StreamReader vfile = new System.IO.StreamReader("Voternumber.txt");
                                            while ((line = vfile.ReadLine()) != null)
                                            {
                                                string[] arr = line.Split(',');
                                                voterfile.Add(Convert.ToInt32(arr[0]), Convert.ToInt32(arr[1]));
                                            }
                                            vfile.Close();
                                            voterfile[Convert.ToInt32(vno)] = 1;
                                            Dictionary<string, string> history = new Dictionary<string, string>();
                                            System.IO.StreamReader hfile = new System.IO.StreamReader("History.txt");
                                            while ((line = hfile.ReadLine()) != null)
                                            {
                                                string[] arr = line.Split(',');
                                                history.Add(arr[0], arr[1]);
                                            }
                                            hfile.Close();
                                            history.Add(vno.ToString(), DateTime.Now.ToString("yyyy-MM-dd hh:mm:ss tt"));

                                            string[] lines = File.ReadAllLines("Result.txt");
                                            string[] array = lines[v - 1].Split(',');
                                            lines[v - 1] = array[0] + ',' + ((Convert.ToInt32(array[1])) + 1).ToString();

                                            using (var stream = new FileStream("Result.txt", FileMode.Truncate))
                                            {
                                                using (var writer = new StreamWriter(stream))
                                                {
                                                    foreach (string str2 in lines)
                                                    {
                                                        writer.WriteLine(str2);
                                                    }
                                                }
                                            }
                                            using (var stream = new FileStream("Voternumber.txt", FileMode.Truncate))
                                            {
                                                using (var writer = new StreamWriter(stream))
                                                {
                                                    foreach (KeyValuePair<int, int> pair in voterfile)
                                                    {
                                                        writer.WriteLine((pair.Key).ToString() + "," + (pair.Value).ToString());
                                                    }
                                                }
                                            }
                                            using (var stream = new FileStream("History.txt", FileMode.Truncate))
                                            {
                                                using (var writer = new StreamWriter(stream))
                                                {
                                                    foreach (KeyValuePair<string, string> pair in history)
                                                    {
                                                        writer.WriteLine((pair.Key) + "," + (pair.Value));
                                                    }
                                                }
                                            }
                                        }
                                        else if (voterfile[Convert.ToInt32(vno)] == 1)
                                        {
                                            byte[] oData = System.Text.Encoding.ASCII.GetBytes("voted");
                                            networkStream.Write(oData, 0, oData.Length);
                                        }
                                        break;
                                    case 2:
                                        Dictionary<string, string> historyRes = new Dictionary<string, string>();
                                        System.IO.StreamReader hf = new System.IO.StreamReader("History.txt");
                                        while ((line = hf.ReadLine()) != null)
                                        {
                                            string[] arr = line.Split(',');
                                            historyRes.Add(arr[0], arr[1]);
                                        }
                                        hf.Close();
                                        string hresult = "";
                                        if (historyRes.ContainsKey(vno))
                                        {
                                            hresult = vno + " " + historyRes[vno];
                                        }
                                        else
                                        {
                                            hresult = "No records found!";
                                        }
                                        byte[] outD = Encoding.ASCII.GetBytes(hresult);
                                        networkStream.Write(outD, 0, outD.Length);

                                        break;
                                    case 3:
                                        string[] resultFile = File.ReadAllLines("Result.txt");
                                        string res = "";
                                        foreach (string r in resultFile)
                                        {
                                            res += r;
                                            res += "\n";
                                        }
                                        byte[] resultAll = Encoding.ASCII.GetBytes(res.Replace(",", "\t"));
                                        networkStream.Write(resultAll, 0, resultAll.Length);
                                        break;

                                }
                            } while (state != "4");
                            exit = true;
                        }
                        else
                        {
                            byte[] msg = System.Text.Encoding.ASCII.GetBytes("invalid");
                            networkStream.Write(msg, 0, msg.Length);
                            exit = true;
                        }
                        if (exit)
                        {
                            break;
                        }
                    }

                    networkStream.Flush();

                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.ToString());
                    continue;
                }
            }
        }
    }
}
