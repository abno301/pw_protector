using System.Collections.Generic;
using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

namespace MyWebApiApp.Models;

public class User
{
    [BsonId]
    public ObjectId Id { get; set; }
    public string Username { get; set; }
    public string PasswordHash { get; set; }
    public List<UserPassword> Passwords { get; set; } = new List<UserPassword>();

    public string GetIdAsString() => Id.ToString();
}
