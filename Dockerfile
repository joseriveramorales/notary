# syntax=docker/dockerfile:1
# ---- build stage: restore + publish with the full SDK ----
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Copy csproj/sln first so package restore is cached when only source changes.
COPY Notary.sln ./
COPY src/Notary.Core/Notary.Core.csproj   src/Notary.Core/
COPY src/Notary.Cli/Notary.Cli.csproj     src/Notary.Cli/
COPY src/Notary.Api/Notary.Api.csproj     src/Notary.Api/
COPY tests/Notary.Tests/Notary.Tests.csproj tests/Notary.Tests/
RUN dotnet restore src/Notary.Api/Notary.Api.csproj

# Copy the rest and publish a framework-dependent build.
COPY . .
RUN dotnet publish src/Notary.Api/Notary.Api.csproj -c Release -o /app --no-restore

# ---- runtime stage: ASP.NET runtime only, no SDK ----
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app ./
ENV ASPNETCORE_URLS=http://+:8080
EXPOSE 8080
# A local PFX or Key Vault can be wired via env vars (NOTARY_KEY_PATH / NOTARY_KEYVAULT_URI);
# with none set the API uses an ephemeral dev key.
ENTRYPOINT ["dotnet", "Notary.Api.dll"]
