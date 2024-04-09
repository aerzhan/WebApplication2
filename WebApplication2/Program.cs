using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authentication.Cookies;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.EntityFrameworkCore;
using WebApplication2;

var builder = WebApplication.CreateBuilder();

string connection = "Server=(localdb)\\mssqllocaldb;Database=applicationdb;Trusted_Connection=True;";
builder.Services.AddDbContext<ApplicationContext>(options => options.UseSqlServer(connection));

builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options => options.LoginPath = "/login");
builder.Services.AddAuthorization();

var app = builder.Build();

app.UseAuthentication();   // добавление middleware аутентификации 
app.UseAuthorization();   // добавление middleware авторизации 

app.MapGet("/login", async (HttpContext context) =>
{
    context.Response.ContentType = "text/html; charset=utf-8";
    // html-форма для ввода логина/пароля
    string loginForm = @"<!DOCTYPE html>
    <html>
    <head>
        <meta charset='utf-8' />
        <title>METANIT.COM</title>
    </head>
    <body>
        <h2>Login Form</h2>
        <form method='post'>
            <p>
                <label>Email</label><br />
                <input name='email' />
            </p>
            <p>
                <label>Password</label><br />
                <input type='password' name='password' />
            </p>
            <input type='submit' value='Login' />
        </form>
    </body>
    </html>";
    await context.Response.WriteAsync(loginForm);
});

app.MapPost("/login", async (string? returnUrl, HttpContext context, ApplicationContext db) =>
{
    // получаем из формы email и пароль
    var form = context.Request.Form;
    // если email и/или пароль не установлены, посылаем статусный код ошибки 400
    if (!form.ContainsKey("email") || !form.ContainsKey("password"))
        return Results.BadRequest("Email и/или пароль не установлены");

    string email = form["email"];
    string password = form["password"];

    var person = db.Users.FirstOrDefault(p => p.Email == email && p.Pasword == password);
    // если пользователь не найден, отправляем статусный код 401
    if (person is null) return Results.Unauthorized();

    var claims = new List<Claim> { new Claim(ClaimTypes.Name, person.Email) };
    // создаем объект ClaimsIdentity
    ClaimsIdentity claimsIdentity = new ClaimsIdentity(claims, "Cookies");
    // установка аутентификационных куки
    await context.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity));
    return Results.Redirect(returnUrl ?? "/");
});

app.MapGet("/logout", async (HttpContext context) =>
{
    await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
    return Results.Redirect("/login");
});

app.Map("/", [Authorize] (ApplicationContext db) => db.Users.ToList());

app.Run();

record class Person(string Email, string Password);