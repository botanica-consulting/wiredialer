# ☎️ WireDialer
A usermode WireGuard client in an idiomatic Golang Dialer style, by [Botanica Software Labs](https://botanica.software)

This is a simple utility library that provides an adapter between a typical WireGuard configuration file and the Golang `Dial` and `DialContext` functions.

A typical use case would be proxying specific connections in cases where you do not want to rely on OS configuration (i.e. routing) to ensure proper tunneling, for instance in security-sensitive contexts, or for masking your origin.


# Example - HTTP client
```go
package main
import (
    "fmt"
    "io"
    "net/http"
    "os"
    "github.com/botanica-consulting/wiredialer"
    )

func main() {
    // Create a new Dialer based on a WireGuard configuration file
    d, err := wiredialer.NewDialerFromFile("wg0.conf")
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }

    // Create a new HTTP client that uses the Dialer
    client := &http.Client{
        Transport: &http.Transport{
            DialContext: d.DialContext,
        },
    }

    // Make a request
    resp, err := client.Get("http://ifconfig.co/city")
    if err != nil {
        fmt.Println(err)
        os.Exit(1)
    }
    defer resp.Body.Close()

    // Print the response body
    io.Copy(os.Stdout, resp.Body)

}
```

Disclaimer: This library is not an official product, use freely at your own risk. 
