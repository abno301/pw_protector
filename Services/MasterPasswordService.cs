using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using MongoDB.Driver;
using MyWebApiApp.Models;

public class MasterPasswordService
{
    private const string MasterPasswordHashFile = "master_hash.txt";
    public string MasterPasswordHash;

    private readonly IMongoCollection<MasterPassword> _userCollection;

    public MasterPasswordService(IMongoClient mongoClient)
    {
        var database = mongoClient.GetDatabase("test"); 
        _userCollection = database.GetCollection<MasterPassword>("users");
    }
    
    public bool VerifyMasterPassword(string masterPassword)
    {
        if (!File.Exists(MasterPasswordHashFile))
        {
            SetMasterPassword(masterPassword);
            return true;
        }

        var storedHash = File.ReadAllText(MasterPasswordHashFile);
        MasterPasswordHash = storedHash;

        return Hash(masterPassword) == storedHash;
    }

    private void SetMasterPassword(string masterPassword)
    {
        var hashedPassword = Hash(masterPassword);
        if (hashedPassword != null)
        {
            MasterPasswordHash = hashedPassword;
        }

        File.WriteAllText(MasterPasswordHashFile, hashedPassword);
    }
    
    public async Task<bool> SaveUserAsync(string username, string masterPassword)
    {
        string passwordHash;
        
        if (!File.Exists(MasterPasswordHashFile))
        {
            // First-time setup, hash and store the new master password
            passwordHash = Hash(masterPassword);
            File.WriteAllText(MasterPasswordHashFile, passwordHash);
        }
        else
        {
            // Verify provided password with stored hash
            var storedHash = File.ReadAllText(MasterPasswordHashFile);
            if (Hash(masterPassword) != storedHash)
            {
                Console.WriteLine("Invalid master password.");
                return false; // Password ni pravi
            }

            passwordHash = storedHash;
        }

        // Save to MongoDB
        var user = new MasterPassword
        {
            Username = username,
            PasswordHash = passwordHash
        };
        await _userCollection.InsertOneAsync(user);
        
        Console.WriteLine("Username and password hash saved to MongoDB.");
        return true;
    }

    private string Hash(string input)
    {
        using var sha256 = SHA256.Create();
        var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(bytes);
    }
}
