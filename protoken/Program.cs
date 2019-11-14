using Microsoft.IdentityModel.Tokens;
using Nancy.Json;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace protoken
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var user = new User { UserId = 1, EmailAddress = "fernando@sendpizza.com", FirstName = "Fernando", LastName = "Oliva" };
            var json = new JavaScriptSerializer().Serialize(user);
            var issuer = "Machete.com/remitente";
            var authority = "MacheteMontenegro";
            //la llave privada debe contener 256 caracteres
            var privateKey = "J6k2eVCTXDp5b97u6gNH5GaaqHDxCmzz2wv3PRPFRsuW2UavK8LGPRauC4VSeaetKTMtVmVzAC8fh8Psvp8PFybEvpYnULHfRpM8TA2an7GFehrLLvawVJdSRqh2unCnWehhh2SJMMg5bktRRapA8EGSgQUV8TCafqdSEHNWnGXTjjsMEjUpaxcADDNZLSYPMyPSfp6qe5LMcd5S9bXH97KeeMGyZTS2U8gp3LGk2kH4J4F3fsytfpe9H9qKwgjb";
            var userJson = new JavaScriptSerializer().Serialize(user);
            var createJwt = await CreateJWTAsync(user, issuer, authority, privateKey, userJson);
            await Console.Out.WriteLineAsync(createJwt);
            await Console.In.ReadLineAsync();
        }

        public static async Task<string> CreateJWTAsync(User user, string issuer, string authority, string symSec, string userJson)       
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var claims = await CreateClaimsIdentities("Datos Usuario en Json "+userJson);

            var token = tokenHandler.CreateJwtSecurityToken(
                issuer: issuer,
                audience: authority,
                subject: claims,
                notBefore: DateTime.UtcNow,
                expires: DateTime.UtcNow.AddDays(1),
                signingCredentials:
                new SigningCredentials(
                    new SymmetricSecurityKey(
                        Encoding.Default.GetBytes(symSec)),
                        SecurityAlgorithms.HmacSha256Signature));

            return tokenHandler.WriteToken(token);
        }

        public static Task<ClaimsIdentity> CreateClaimsIdentities(string userJson)
        {
            ClaimsIdentity claimsIdentity = new ClaimsIdentity();
            claimsIdentity.AddClaim(new Claim(ClaimTypes.UserData, userJson));
            return Task.FromResult(claimsIdentity);
        }
        public class User
        {
            public int UserId { get; set; }
            public string EmailAddress { get; set; }
            public string FullName { get; set; }
            public string FirstName { get; set; }
            public string LastName { get; set; }
        }
    }
}
