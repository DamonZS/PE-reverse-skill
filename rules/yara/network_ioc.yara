rule EmbeddedNetworkIOC : network ioc {
    meta:
        description = "Highlights embedded HTTP or DNS-looking IOC strings"
        severity = "low"
        author = "Worker 2"
    strings:
        $http = "http://" ascii wide nocase
        $https = "https://" ascii wide nocase
        $ua = "User-Agent" ascii wide nocase
        $dns = ".onion" ascii wide nocase
        $socket = "WSAStartup" ascii wide nocase
    condition:
        2 of them
}