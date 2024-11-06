using System;
using System.Text;
using System.Text.RegularExpressions;

public class PasswordStrengthChecker
{
    public static string CheckPasswordStrength(string password)
    {
        if (string.IsNullOrEmpty(password))
        {
            return "Password cannot be empty.";
        }

        int score = 0;

        if (password.Length >= 8) score++;
        if (password.Length >= 12) score++;
        if (Regex.IsMatch(password, @"[a-z]") && Regex.IsMatch(password, @"[A-Z]")) score++;
        if (Regex.IsMatch(password, @"[0-9]")) score++;
        if (Regex.IsMatch(password, @"[!@#$%^&*(),.?""{}|<>]")) score++;

        bool hasBadEnding = Regex.IsMatch(password, @"[!@#$%^&*(),.?""{}|<>]$|[0-9]$");
        bool isCapitalizationLimited = Regex.IsMatch(password, @"^[A-Z][a-z]+$");
        bool hasRepetitiveCharacters = Regex.IsMatch(password, @"(.)\1{2,}");

        if (!hasBadEnding && !isCapitalizationLimited && !hasRepetitiveCharacters) score += 2;

        return score switch
        {
            0 => "Very Weak",
            1 => "Weak",
            2 or 3 => "Moderate",
            4 or 5 => "Strong",
            6 => "Very Strong",
            7 => "Excellent",
            _ => "Invalid Password"
        };
    }

    public static string GeneratePassword(bool useUppercase, bool useLowercase, bool useSymbols, bool useNumbers, int length)
    {
        if (length <= 0)
        {
            throw new ArgumentException("Password length must be greater than 0.");
        }

        const string uppercaseLetters = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const string lowercaseLetters = "abcdefghijklmnopqrstuvwxyz";
        const string symbols = "!@#$%^&*(),.?\"{}|<>[]";
        const string numbers = "0123456789";

        StringBuilder characterPool = new StringBuilder();
        characterPool.Append(lowercaseLetters);

        if (useUppercase) characterPool.Append(uppercaseLetters);
        if (useSymbols) characterPool.Append(symbols);
        if (useNumbers) characterPool.Append(numbers);

        StringBuilder password = new StringBuilder();
        Random random = new Random();

        for (int i = 0; i < length; i++)
        {
            int randomIndex = random.Next(characterPool.Length);
            password.Append(characterPool[randomIndex]);
        }

        return password.ToString();
    }
}
