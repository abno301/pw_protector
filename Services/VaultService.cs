using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

public class VaultService
{
    private const string VaultFile = "vault.json";

    public static void AddAccount(string site, string username, string passwordEnc)
    {
        var account = new { Site = site, Username = username, Password = passwordEnc };

        List<dynamic> accounts;
        if (File.Exists(VaultFile))
        {
            var json = File.ReadAllText(VaultFile);
            accounts = JsonSerializer.Deserialize<List<dynamic>>(json) ?? new List<dynamic>();
        }
        else
        {
            accounts = new List<dynamic>();
        }

        accounts.Add(account);
        var updatedJson = JsonSerializer.Serialize(accounts, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(VaultFile, updatedJson);

        Console.WriteLine($"Account for {site} added.");
    }

    public static Dictionary<string, object>? GetAccount(string site)
    {
        if (!File.Exists(VaultFile))
        {
            Console.WriteLine("No accounts found.");
            return null;
        }

        var json = File.ReadAllText(VaultFile);
        var accounts = JsonSerializer.Deserialize<List<Dictionary<string, object>>>(json);

        return accounts?.FirstOrDefault(a => a["Site"].ToString() == site);
    }
}
