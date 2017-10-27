using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.IO;



namespace voter_cli
{
    class Program
    {
        public static byte[] Encrypt(string plainText, int counter, string serType)
        {

            CspParameters cspParams = null;
            RSACryptoServiceProvider rsaProvider = null;
            StreamReader publicKeyFile = null;

            string publicKeyText = "";

            byte[] plainBytes = null;
            byte[] encryptedBytes = null;

            try
            {

                cspParams = new CspParameters();
                cspParams.ProviderType = 1;

                rsaProvider = new RSACryptoServiceProvider(cspParams);

                publicKeyFile = File.OpenText(@"c:\" + serType + "PublicKey" + counter.ToString() + ".xml");
                publicKeyText = publicKeyFile.ReadToEnd();
                rsaProvider.FromXmlString(publicKeyText);
                plainBytes = Encoding.Unicode.GetBytes(plainText);
                encryptedBytes = rsaProvider.Encrypt(plainBytes, false);
                return encryptedBytes;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
                return encryptedBytes;
            }


        }
        static void Main(string[] args)
        {
            if (args.Length == 2)
            {
                IPAddress add = null;
                IPAddress[] addresslist = Dns.GetHostAddresses(args[0]);
                foreach (IPAddress ad in addresslist)
                {
                    if (ad.AddressFamily == AddressFamily.InterNetwork)
                    {
                        add = ad;
                    }
                }
                IPAddress[] IPs = Dns.GetHostAddresses(add.ToString());

                Socket s = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);

                try
                {
                    s.Connect(IPs[0], Convert.ToInt32(args[1]));
                    byte[] type = new byte[4];
                    s.Receive(type);
                    string serType = Encoding.ASCII.GetString(type);

                    while (true)
                    {
                        if (serType.StartsWith("LA"))
                        {
                            string[] array = serType.Split('$');
                            Console.WriteLine("Enter His/Her Name:");
                            string name = Console.ReadLine();
                            Console.WriteLine("Enter SSN Number:");
                            string ssn = Console.ReadLine();
                            string creds = name + "$" + ssn;
                            string outdata = "";
                            byte[] oByte = Encrypt(creds, Convert.ToInt32(array[1]), array[0]);
                            s.Send(oByte);
                            byte[] iByte = new byte[256];
                            int i = s.Receive(iByte);
                            outdata = System.Text.Encoding.ASCII.GetString(iByte, 0, i);
                            if (outdata.Equals("no"))
                            {
                                Console.WriteLine("You are not eligible to vote");
                                break;
                            }
                            else if (outdata.Equals("invalid"))
                            {
                                Console.WriteLine("Invalid credentials");
                                break;
                            }
                            else
                            {
                                Console.WriteLine("V Number: {0}", outdata);
                                break;
                            }
                        }

                        if (serType.StartsWith("VF"))
                        {
                            string[] array = serType.Split('$');
                            byte[] oByte = Encoding.ASCII.GetBytes("VC");
                            s.Send(oByte);
                            Console.WriteLine("Enter Validation Number:");
                            string valno = Console.ReadLine();
                            byte[] o2Byte = Encrypt(valno, Convert.ToInt32(array[1]), array[0]);
                            s.Send(o2Byte);
                            byte[] buffer = new byte[256];
                            int i = s.Receive(buffer);
                            string status = System.Text.Encoding.ASCII.GetString(buffer, 0, i);
                            if (status.StartsWith("invalid"))
                            {
                                Console.WriteLine("Invalid Verification Number.");
                                break;
                            }

                            if (status.StartsWith("valid"))
                            {
                                int val;

                                do
                                {
                                    Console.WriteLine("Please enter a number (1-4):");
                                    Console.WriteLine("1. Vote");
                                    Console.WriteLine("2. My vote history");
                                    Console.WriteLine("3. View the latest results");
                                    Console.WriteLine("4. Quit");
                                    val = Convert.ToInt32(Console.ReadLine());
                                    byte[] send = new byte[1];
                                    switch (val)
                                    {
                                        case 1:
                                           
                                            send = Encoding.ASCII.GetBytes("1");
                                            s.Send(send);
                                            byte[] buffer2 = new byte[256];                                            
                                            int p = s.Receive(buffer2);
                                            string data = System.Text.Encoding.ASCII.GetString(buffer2, 0, p);
                                            if (data.StartsWith("not voted"))
                                            {
                                                Console.WriteLine("Please enter a number (1-2)");
                                                Console.WriteLine("1. Bob");
                                                Console.WriteLine("2. John");
                                                string vote = Console.ReadLine();
                                                byte[] sendVote = Encoding.ASCII.GetBytes(vote);
                                                s.Send(sendVote);
                                            }
                                            if (data.StartsWith("voted"))
                                            {
                                                Console.WriteLine("You have already voted!");
                                            }
                                            break;
                                        case 2:
                                            send = Encoding.ASCII.GetBytes("2");
                                            s.Send(send);
                                            byte[] buffer3 = new byte[256];
                                            int q = s.Receive(buffer3);
                                            string results = System.Text.Encoding.ASCII.GetString(buffer3, 0, q);
                                            Console.WriteLine(results);
                                            break;
                                        case 3:
                                            send = Encoding.ASCII.GetBytes("3");
                                            s.Send(send);
                                            byte[] buffer4 = new byte[256];
                                            int r = s.Receive(buffer4);
                                            string history = System.Text.Encoding.ASCII.GetString(buffer4, 0, r);
                                            Console.WriteLine(history);
                                            break;
                                    }
                                } while (val != 4);
                                byte[] exit = Encoding.ASCII.GetBytes("4");
                                s.Send(exit);
                                break;
                            }
                        }


                    }
                    Environment.Exit(0);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }


                Console.ReadLine();
            }
        }


    }
}

