# Use the official .NET 8 SDK image to build the app
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build-env
WORKDIR /app

# Copy the .csproj file and restore any dependencies (using a cache for efficiency)
COPY *.csproj ./
RUN dotnet restore

# Copy the rest of the application source code and build the app
COPY . ./
RUN dotnet publish -c Release -o /out

# Use the .NET 8 runtime image to run the app
FROM mcr.microsoft.com/dotnet/aspnet:8.0
WORKDIR /app
COPY --from=build-env /out .

# Expose the port the app runs on
EXPOSE 5144

# Define the entry point to run the app
ENTRYPOINT ["dotnet", "MyWebApiApp.dll"]
