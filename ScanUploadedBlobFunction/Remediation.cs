using Azure.Storage.Blobs;
using Microsoft.Extensions.Logging;
using System;
using System.IO;
using System.Text;
using System.Threading.Tasks;
using Azure.Storage.Blobs.Models;

namespace ScanUploadedBlobFunction
{
    public class Remediation
    {
        private ScanResults scanResults { get; }
        private ILogger log { get; }
        public Remediation(ScanResults scanResults, ILogger log)
        {
            this.scanResults = scanResults;
            this.log = log;
        }

        public void Start()
        {
            string srcContainerName = Environment.GetEnvironmentVariable("targetContainerName");

            if (scanResults.isThreat)
            {
                log.LogInformation($"A malicious file was detected, file name: {scanResults.fileName}, threat type: {scanResults.threatType}");
                try
                {
                    ReplaceBlob(scanResults.fileName, srcContainerName, log).GetAwaiter().GetResult();
                    log.LogInformation("A malicious file was detected. It has been removed and replaced with an placeholder.");
                }

                catch (Exception e)
                {
                    log.LogError($"A malicious file was detected, but remediation failed. {e.Message}");
                }
            }
        }

        private static async Task ReplaceBlob(string srcBlobName, string srcContainerName, ILogger log)
        {
            var connectionString = Environment.GetEnvironmentVariable("windefenderstorage");
            var srcContainer = new BlobContainerClient(connectionString, srcContainerName);

            var srcBlob = srcContainer.GetBlobClient(srcBlobName);

            await srcBlob.UploadAsync(GenerateStream("This blob was found to contain malware and has been removed."), true);
        }

        private static Stream GenerateStream(string value)
        {
            return new MemoryStream(Encoding.UTF8.GetBytes(value));
        }
    }
}
