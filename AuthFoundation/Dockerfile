FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

COPY AuthFoundation/AuthFoundation.csproj AuthFoundation/
RUN dotnet restore AuthFoundation/AuthFoundation.csproj

COPY AuthFoundation/ AuthFoundation/
RUN dotnet publish AuthFoundation/AuthFoundation.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_HTTP_PORTS=8080
EXPOSE 8080
ENTRYPOINT ["dotnet", "AuthFoundation.dll"]
