using System.Net.NetworkInformation;

namespace CasDotnetSdk.Configuration
{
    internal class Networking
    {
        public string MacAddress { get; set; }
        public Networking()
        {
            this.GetMacAddressOfMachine();
        }

        private void GetMacAddressOfMachine()
        {
            // Get all network interfaces on the system
            NetworkInterface[] networkInterfaces = NetworkInterface.GetAllNetworkInterfaces();

            // Find the network interface that is active and has internet connectivity
            NetworkInterface activeInterface = null;
            foreach (var networkInterface in networkInterfaces)
            {
                if (networkInterface.OperationalStatus == OperationalStatus.Up &&
                    HasInternetConnectivity(networkInterface))
                {
                    activeInterface = networkInterface;
                    break;
                }
            }

            // Check if an active network interface is found
            if (activeInterface != null)
            {
                this.MacAddress = activeInterface.GetPhysicalAddress().ToString();
            }
        }

        private bool HasInternetConnectivity(NetworkInterface networkInterface)
        {
            try
            {
                // You can implement your logic to check for internet connectivity here
                // For simplicity, we are just pinging a well-known public DNS server (8.8.8.8)
                using (Ping ping = new Ping())
                {
                    PingReply reply = ping.Send("8.8.8.8", 1000);
                    return reply.Status == IPStatus.Success;
                }
            }
            catch
            {
                return false;
            }
        }
    }
}