using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using MongoDB.Driver;
using MyWebApiApp.Models;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("http://0.0.0.0:5144");

var mongoUri = Environment.GetEnvironmentVariable("MONGO_URI") ?? "mongodb://root:example@localhost:27017";

// Register IMongoClient as a singleton
builder.Services.AddSingleton<IMongoClient>(sp => new MongoClient(mongoUri));


builder.Services.AddSingleton<MasterPasswordService>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

// set master password
app.MapPost("/masterPassword", async (PasswordsRequest masterPasswordRequest, MasterPasswordService masterService) => {
        Console.WriteLine(masterPasswordRequest.MasterPassword);

        bool result = await masterService.SaveUserAsync(masterPasswordRequest.Username, masterPasswordRequest.MasterPassword);         
        if (!result)
        {
            return Results.BadRequest("Invalid master password");
        }
        
         return Results.Ok(new { Username = masterPasswordRequest.Username });    })
    .WithName("CreateMasterPassword")
    .WithOpenApi();

// add password to password protector
app.MapPost("/password", async ([FromBody]CreatePasswordRequest request, IMongoClient mongoClient, MasterPasswordService masterService) => {
        Console.WriteLine(request);

        if (!masterService.VerifyMasterPassword(request.MasterPassword))
        {
            Console.WriteLine("Invalid master password.");
            return Results.BadRequest("Invalid master password");
        }

        var encryptionService = new EncryptionService(masterService.MasterPasswordHash);
        var encrypted = encryptionService.Encrypt(request.Password);

        Console.WriteLine("Encrypted: " + encrypted);

        var database = mongoClient.GetDatabase("test"); // Use the actual database name
        var usersCollection = database.GetCollection<User>("users");

        var user = await usersCollection.Find(u => u.Username == request.Username).FirstOrDefaultAsync();

        if (user == null)
        {
            Console.WriteLine("User not found.");
            return Results.BadRequest("User not found");
        }

        user.Passwords.Add(new UserPassword(encrypted, request.Description));

        var updateDefinition = Builders<User>.Update.Set(u => u.Passwords, user.Passwords);
        await usersCollection.UpdateOneAsync(u => u.Username == request.Username, updateDefinition);

        return Results.Ok(new { Encrypted = encrypted });
    })
    .WithName("AddPassword")
    .WithOpenApi();

// get all passwords from user master password
app.MapPost("/password/{username}", async ([FromBody]PasswordsRequest request, MasterPasswordService masterService) => {
        Console.WriteLine(request);

        var user = await masterService.GetUserAsync(request.Username);
        if (user == null || !masterService.VerifyMasterPassword(request.MasterPassword))
        {
            Console.WriteLine("Invalid password.");
            return Results.BadRequest("Invalid master password");
        }

        var encryptionService = new EncryptionService(masterService.MasterPasswordHash);

        // Decrypt passwords and map to objects with password and description
        var decryptedPasswords = user.Passwords.Select(p => new 
        {
            Password = encryptionService.Decrypt(p.EncryptedPassword),
            Description = p.Description
        }).ToList();

        Console.WriteLine("Decrypted Passwords with Descriptions: ");
        decryptedPasswords.ForEach(p => Console.WriteLine($"Password: {p.Password}, Description: {p.Description}"));

        return Results.Ok(new { Passwords = decryptedPasswords });
    })
    .WithName("GetAllPasswords")
    .WithOpenApi();

// delete user and all their passwords
app.MapDelete("/user/{username}", async (string username, IMongoClient mongoClient) =>
    {
        var database = mongoClient.GetDatabase("test"); // Use the actual database name
        var usersCollection = database.GetCollection<User>("users");

        // Attempt to delete the user
        var deleteResult = await usersCollection.DeleteOneAsync(u => u.Username == username);

        if (deleteResult.DeletedCount == 0)
        {
            Console.WriteLine($"User with username '{username}' not found.");
            return Results.NotFound($"User with username '{username}' not found.");
        }

        Console.WriteLine($"User with username '{username}' successfully deleted.");
        return Results.Ok($"User with username '{username}' successfully deleted.");
    })
    .WithName("DeleteUser")
    .WithOpenApi();



app.Run();

public record CreatePasswordRequest(
    string Username,
    string MasterPassword,
    string Password,
    string Description
);
public record PasswordsRequest(string Username, string MasterPassword);

public record UserPassword(
    string EncryptedPassword,
    string Description
);