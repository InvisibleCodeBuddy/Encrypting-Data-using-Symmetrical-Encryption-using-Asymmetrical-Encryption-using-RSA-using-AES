using CryptoHelper;
using System.Text;
//Sample publickey
//Included in this project
string publickey = "publicKey.xml";

//Sample privatekey
//Included in this project
string privatekey = "privateKey.xml";

string data = "Sample string";

Console.WriteLine("Please provide a publickey file path or press 'Enter' to use sample keyfile:");
string tmp = Console.ReadLine();
if (!string.IsNullOrEmpty(tmp))
    publickey = tmp;

Console.WriteLine("Please provide a privatekey file path or press 'Enter' to use sample keyfile:");
tmp = Console.ReadLine();
if (!string.IsNullOrEmpty(tmp))
    privatekey = tmp;

Console.WriteLine("Please provide data to be encrypted:");
tmp = Console.ReadLine();
if (tmp.Length > 0)
    data = tmp;

var encdata = RSAHelper.EncryptContent(publickey, data);

var encstring = Encoding.UTF8.GetString(encdata);

Console.WriteLine($"Encrypted Data:\n{encstring}\n\n");

Console.WriteLine("Please provide a publickey file path or press 'Enter' to use sample keyfile:");
tmp = Console.ReadLine();
if (!string.IsNullOrEmpty(tmp))
    publickey = tmp;

Console.WriteLine("Please provide a privatekey file path or press 'Enter' to use sample keyfile:");
tmp = Console.ReadLine();
if (!string.IsNullOrEmpty(tmp))
    privatekey = tmp;

var decdata = RSAHelper.DecryptContent(privatekey, encdata);

Console.WriteLine($"Decrypted Data:\n{decdata}\n\n");

Console.WriteLine("Press any key to exit..");
Console.Read();
