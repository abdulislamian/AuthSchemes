using AuthSchemesAndOptions.Extensions;
using AuthSchemesAndOptions.Mappings;
using AuthSchemesAndOptions.Repositories;
using JWTAuthentication.Data;
using Microsoft.EntityFrameworkCore;


var builder = WebApplication.CreateBuilder(args);


builder.Services.AddJwtConfiguration(builder.Configuration);

// Add services to the container.
builder.Services.AddControllers();

builder.Services.AddDbContext<ApplicationDbContext>(options => options.UseSqlServer(
    builder.Configuration.GetConnectionString("AppConnection")));
builder.Services.ConfigureIdentity();

builder.Services.AddScoped<IStudentRepository, SQLStudentRepository>();
builder.Services.AddScoped<ITokenRepository, TokenRepository>();

builder.Services.ConfigureAuthentication(builder.Configuration);
builder.Services.ConfigureAuthorization();

builder.Services.AddAutoMapper(typeof(AutoMapperProfiles));
builder.Services.AddHttpContextAccessor();



// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.ConfigureSwaggerGen();
//builder.Services.Configure<JwtConfiguration>(builder.Configuration.GetSection("JWT"));


var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    //app.UseSwaggerUI();
    app.UseSwaggerUI(options =>
    {
        options.DefaultModelsExpandDepth(-1);
    });
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
