using CryptoHelper;
using System.Text;

//Sample key
string key = "E3AE5714F04FCDE7ED0CDE3148F153EE";

//Sample Secret
//A Secret Key is shared between the sender and the receiver of cipher text to encrypt and decrypt
string iv = "5F4DCC3B5AA765D6";

string data = "This is a sample string to be encrypted";

Console.WriteLine("Please provide an encryption key with 32 characters or press 'Enter' to use sample key:");
string tmp = Console.ReadLine();
if (tmp.Length == 32)
    key = tmp;

Console.WriteLine("Please provide an encryption secret with 16 characters or Press 'Enter' to use sample secret:");
tmp = Console.ReadLine();
if (tmp.Length == 16)
    iv = tmp;

Console.WriteLine("Please provide data to be encrypted:");
tmp= Console.ReadLine();
if (tmp.Length >0)
    data  = tmp;

if (key.Length != 32)
{
    Console.WriteLine($"Provided string was {key.Length} characters.");
    return;
}

if (iv.Length !=16 )
{
    Console.WriteLine($"Provided secret was {iv.Length} characters.");
    return;
}

var encdata = AESHelper.EncryptContent(key, iv, data );

var encstring = Encoding.UTF8.GetString(encdata);

Console.WriteLine($"Encrypted Data:\n{encstring}\n\n");

Console.WriteLine("Please provide an decryption key with 32 characters or press 'Enter' to use sample key:");
tmp = Console.ReadLine();
if (tmp.Length == 32)
    key = tmp;

Console.WriteLine("Please provide an decryption secret with 16 characters or Press 'Enter' to use sample secret:");
tmp = Console.ReadLine();
if (tmp.Length == 16)
    iv = tmp;

var decdata = AESHelper.DecryptContent(key, iv, encdata);

Console.WriteLine($"Decrypted Data:\n{decdata}\n\n");

Console.WriteLine("Press any key to exit..");
Console.Read();