// Copyright (c) Tailscale Inc & AUTHORS
// SPDX-License-Identifier: BSD-3-Clause

package portmapper

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"reflect"
	"regexp"
	"sync/atomic"
	"testing"

	"tailscale.com/tstest"
)

// Google Wifi
const (
	googleWifiUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nUSN: uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece::urn:schemas-upnp-org:device:InternetGatewayDevice:2\r\nEXT:\r\nSERVER: Linux/5.4.0-1034-gcp UPnP/1.1 MiniUPnPd/1.9\r\nLOCATION: http://192.168.86.1:5000/rootDesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: 1\r\nBOOTID.UPNP.ORG: 1\r\nCONFIGID.UPNP.ORG: 1337\r\n\r\n"

	googleWifiRootDescXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0"><specVersion><major>1</major><minor>0</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:2</deviceType><friendlyName>OnHub</friendlyName><manufacturer>Google</manufacturer><manufacturerURL>http://google.com/</manufacturerURL><modelDescription>Wireless Router</modelDescription><modelName>OnHub</modelName><modelNumber>1</modelNumber><modelURL>https://on.google.com/hub/</modelURL><serialNumber>00000000</serialNumber><UDN>uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece</UDN><serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><serviceId>urn:upnp-org:serviceId:Layer3Forwarding1</serviceId><controlURL>/ctl/L3F</controlURL><eventSubURL>/evt/L3F</eventSubURL><SCPDURL>/L3F.xml</SCPDURL></service><service><serviceType>urn:schemas-upnp-org:service:DeviceProtection:1</serviceType><serviceId>urn:upnp-org:serviceId:DeviceProtection1</serviceId><controlURL>/ctl/DP</controlURL><eventSubURL>/evt/DP</eventSubURL><SCPDURL>/DP.xml</SCPDURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:2</deviceType><friendlyName>WANDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>WAN Device</modelDescription><modelName>WAN Device</modelName><modelNumber>20210414</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>00000000</serialNumber><UDN>uuid:a9708184-a6c0-413a-bbac-11bcf7e30ecf</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId><controlURL>/ctl/CmnIfCfg</controlURL><eventSubURL>/evt/CmnIfCfg</eventSubURL><SCPDURL>/WANCfg.xml</SCPDURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:2</deviceType><friendlyName>WANConnectionDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>MiniUPnP daemon</modelDescription><modelName>MiniUPnPd</modelName><modelNumber>20210414</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>00000000</serialNumber><UDN>uuid:a9708184-a6c0-413a-bbac-11bcf7e30ec0</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:2</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL><SCPDURL>/WANIPCn.xml</SCPDURL></service></serviceList></device></deviceList></device></deviceList><presentationURL>http://testwifi.here/</presentationURL></device></root>`

	// pfSense 2.5.0-RELEASE / FreeBSD 12.2-STABLE
	pfSenseUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=120\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nEXT:\r\nSERVER: FreeBSD/12.2-STABLE UPnP/1.1 MiniUPnPd/2.2.1\r\nLOCATION: http://192.168.1.1:2189/rootDesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: 1627958564\r\nBOOTID.UPNP.ORG: 1627958564\r\nCONFIGID.UPNP.ORG: 1337\r\n\r\n"

	pfSenseRootDescXML = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0" configId="1337"><specVersion><major>1</major><minor>1</minor></specVersion><device><deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType><friendlyName>FreeBSD router</friendlyName><manufacturer>FreeBSD</manufacturer><manufacturerURL>http://www.freebsd.org/</manufacturerURL><modelDescription>FreeBSD router</modelDescription><modelName>FreeBSD router</modelName><modelNumber>2.5.0-RELEASE</modelNumber><modelURL>http://www.freebsd.org/</modelURL><serialNumber>BEE7052B</serialNumber><UDN>uuid:bee7052b-49e8-3597-b545-55a1e38ac11</UDN><serviceList><service><serviceType>urn:schemas-upnp-org:service:Layer3Forwarding:1</serviceType><serviceId>urn:upnp-org:serviceId:L3Forwarding1</serviceId><SCPDURL>/L3F.xml</SCPDURL><controlURL>/ctl/L3F</controlURL><eventSubURL>/evt/L3F</eventSubURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType><friendlyName>WANDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>WAN Device</modelDescription><modelName>WAN Device</modelName><modelNumber>20210205</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>BEE7052B</serialNumber><UDN>uuid:bee7052b-49e8-3597-b545-55a1e38ac12</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANCommonInterfaceConfig:1</serviceType><serviceId>urn:upnp-org:serviceId:WANCommonIFC1</serviceId><SCPDURL>/WANCfg.xml</SCPDURL><controlURL>/ctl/CmnIfCfg</controlURL><eventSubURL>/evt/CmnIfCfg</eventSubURL></service></serviceList><deviceList><device><deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType><friendlyName>WANConnectionDevice</friendlyName><manufacturer>MiniUPnP</manufacturer><manufacturerURL>http://miniupnp.free.fr/</manufacturerURL><modelDescription>MiniUPnP daemon</modelDescription><modelName>MiniUPnPd</modelName><modelNumber>20210205</modelNumber><modelURL>http://miniupnp.free.fr/</modelURL><serialNumber>BEE7052B</serialNumber><UDN>uuid:bee7052b-49e8-3597-b545-55a1e38ac13</UDN><UPC>000000000000</UPC><serviceList><service><serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType><serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId><SCPDURL>/WANIPCn.xml</SCPDURL><controlURL>/ctl/IPConn</controlURL><eventSubURL>/evt/IPConn</eventSubURL></service></serviceList></device></deviceList></device></deviceList><presentationURL>https://192.168.1.1/</presentationURL></device></root>`

	// Sagemcom FAST3890V3, https://github.com/tailscale/tailscale/issues/3557
	sagemcomUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Tue, 14 Dec 2021 07:51:29 GMT\r\nEXT:\r\nLOCATION: http://192.168.0.1:49153/69692b70/gatedesc0b.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: cabd6488-1dd1-11b2-9e52-a7461e1f098e\r\nSERVER: \r\nUser-Agent: redsonic\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:75802409-bccb-40e7-8e6c-fa095ecce13e::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"

	// Huawei, https://github.com/tailscale/tailscale/issues/6320
	huaweiUPnPDisco = "HTTP/1.1 200 OK\r\nCACHE-CONTROL: max-age=1800\r\nDATE: Fri, 25 Nov 2022 07:04:37 GMT\r\nEXT:\r\nLOCATION: http://192.168.1.1:49652/49652gatedesc.xml\r\nOPT: \"http://schemas.upnp.org/upnp/1/0/\"; ns=01\r\n01-NLS: ce8dd8b0-732d-11be-a4a1-a2b26c8915fb\r\nSERVER: Linux/4.4.240, UPnP/1.0, Portable SDK for UPnP devices/1.12.1\r\nX-User-Agent: UPnP/1.0 DLNADOC/1.50\r\nST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\nUSN: uuid:00e0fc37-2525-2828-2500-0C31DCD93368::urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n\r\n"
)

func TestParseUPnPDiscoResponse(t *testing.T) {
	tests := []struct {
		name    string
		headers string
		want    uPnPDiscoResponse
	}{
		{"google", googleWifiUPnPDisco, uPnPDiscoResponse{
			Location: "http://192.168.86.1:5000/rootDesc.xml",
			Server:   "Linux/5.4.0-1034-gcp UPnP/1.1 MiniUPnPd/1.9",
			USN:      "uuid:a9708184-a6c0-413a-bbac-11bcf7e30ece::urn:schemas-upnp-org:device:InternetGatewayDevice:2",
		}},
		{"pfsense", pfSenseUPnPDisco, uPnPDiscoResponse{
			Location: "http://192.168.1.1:2189/rootDesc.xml",
			Server:   "FreeBSD/12.2-STABLE UPnP/1.1 MiniUPnPd/2.2.1",
			USN:      "uuid:bee7052b-49e8-3597-b545-55a1e38ac11::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		}},
		{"sagemcom", sagemcomUPnPDisco, uPnPDiscoResponse{
			Location: "http://192.168.0.1:49153/69692b70/gatedesc0b.xml",
			Server:   "",
			USN:      "uuid:75802409-bccb-40e7-8e6c-fa095ecce13e::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		}},
		{"huawei", huaweiUPnPDisco, uPnPDiscoResponse{
			Location: "http://192.168.1.1:49652/49652gatedesc.xml",
			Server:   "Linux/4.4.240, UPnP/1.0, Portable SDK for UPnP devices/1.12.1",
			USN:      "uuid:00e0fc37-2525-2828-2500-0C31DCD93368::urn:schemas-upnp-org:device:InternetGatewayDevice:1",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUPnPDiscoResponse([]byte(tt.headers))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("unexpected result:\n got: %+v\nwant: %+v\n", got, tt.want)
			}
		})
	}
}

func TestGetUPnPClient(t *testing.T) {
	tests := []struct {
		name    string
		xmlBody string
		want    string
		wantLog string
	}{
		{
			"google",
			googleWifiRootDescXML,
			"*internetgateway2.WANIPConnection2",
			"saw UPnP type WANIPConnection2 at http://127.0.0.1:NNN/rootDesc.xml; OnHub (Google)\n",
		},
		{
			"pfsense",
			pfSenseRootDescXML,
			"*internetgateway2.WANIPConnection1",
			"saw UPnP type WANIPConnection1 at http://127.0.0.1:NNN/rootDesc.xml; FreeBSD router (FreeBSD)\n",
		},
		// TODO(bradfitz): find a PPP one in the wild
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.RequestURI == "/rootDesc.xml" {
					io.WriteString(w, tt.xmlBody)
					return
				}
				http.NotFound(w, r)
			}))
			defer ts.Close()
			gw, _ := netip.AddrFromSlice(ts.Listener.Addr().(*net.TCPAddr).IP)
			gw = gw.Unmap()
			var logBuf tstest.MemLogger
			c, err := getUPnPClient(context.Background(), logBuf.Logf, DebugKnobs{}, gw, uPnPDiscoResponse{
				Location: ts.URL + "/rootDesc.xml",
			})
			if err != nil {
				t.Fatal(err)
			}
			got := fmt.Sprintf("%T", c)
			if got != tt.want {
				t.Errorf("got %v; want %v", got, tt.want)
			}
			gotLog := regexp.MustCompile(`127\.0\.0\.1:\d+`).ReplaceAllString(logBuf.String(), "127.0.0.1:NNN")
			if gotLog != tt.wantLog {
				t.Errorf("logged %q; want %q", gotLog, tt.wantLog)
			}
		})
	}
}

func TestGetUPnPPortMapping(t *testing.T) {
	igd, err := NewTestIGD(t.Logf, TestIGDOptions{UPnP: true})
	if err != nil {
		t.Fatal(err)
	}
	defer igd.Close()

	c := newTestClient(t, igd)
	t.Logf("Listening on upnp=%v", c.testUPnPPort)
	defer c.Close()

	c.debug.VerboseLogs = true

	// This is a very basic fake UPnP server handler.
	var sawRequestWithLease atomic.Bool
	igd.SetUPnPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("got UPnP request %s %s", r.Method, r.URL.Path)
		switch r.URL.Path {
		case "/rootDesc.xml":
			io.WriteString(w, testRootDesc)
		case "/ctl/IPConn":
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Errorf("error reading request body: %v", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			// Decode the request type.
			var outerRequest struct {
				Body struct {
					Request struct {
						XMLName xml.Name
					} `xml:",any"`
					Inner string `xml:",innerxml"`
				} `xml:"Body"`
			}
			if err := xml.Unmarshal(body, &outerRequest); err != nil {
				t.Errorf("bad request: %v", err)
				http.Error(w, "bad request", http.StatusBadRequest)
				return
			}

			requestType := outerRequest.Body.Request.XMLName.Local
			upnpRequest := outerRequest.Body.Inner
			t.Logf("UPnP request: %s", requestType)

			switch requestType {
			case "AddPortMapping":
				// Decode a minimal body to determine whether we skip the request or not.
				var req struct {
					Protocol       string `xml:"NewProtocol"`
					InternalPort   string `xml:"NewInternalPort"`
					ExternalPort   string `xml:"NewExternalPort"`
					InternalClient string `xml:"NewInternalClient"`
					LeaseDuration  string `xml:"NewLeaseDuration"`
				}
				if err := xml.Unmarshal([]byte(upnpRequest), &req); err != nil {
					t.Errorf("bad request: %v", err)
					http.Error(w, "bad request", http.StatusBadRequest)
					return
				}

				if req.Protocol != "UDP" {
					t.Errorf(`got Protocol=%q, want "UDP"`, req.Protocol)
				}
				if req.LeaseDuration != "0" {
					// Return a fake error to ensure that we fall back to a permanent lease.
					io.WriteString(w, testAddPortMappingPermanentLease)
					sawRequestWithLease.Store(true)
				} else {
					// Success!
					io.WriteString(w, testAddPortMappingResponse)
				}
			case "GetExternalIPAddress":
				io.WriteString(w, testGetExternalIPAddressResponse)

			case "DeletePortMapping":
				// Do nothing for test

			default:
				t.Errorf("unhandled UPnP request type %q", requestType)
				http.Error(w, "bad request", http.StatusBadRequest)
			}
		default:
			t.Logf("ignoring request")
			http.NotFound(w, r)
		}
	}))

	ctx := context.Background()
	res, err := c.Probe(ctx)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !res.UPnP {
		t.Errorf("didn't detect UPnP")
	}

	gw, myIP, ok := c.gatewayAndSelfIP()
	if !ok {
		t.Fatalf("could not get gateway and self IP")
	}
	t.Logf("gw=%v myIP=%v", gw, myIP)

	ext, ok := c.getUPnPPortMapping(ctx, gw, netip.AddrPortFrom(myIP, 12345), 0)
	if !ok {
		t.Fatal("could not get UPnP port mapping")
	}
	if got, want := ext.Addr(), netip.MustParseAddr("123.123.123.123"); got != want {
		t.Errorf("bad external address; got %v want %v", got, want)
	}
	if !sawRequestWithLease.Load() {
		t.Errorf("wanted request with lease, but didn't see one")
	}
	t.Logf("external IP: %v", ext)
}

const testRootDesc = `<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0" configId="1337">
  <specVersion>
    <major>1</major>
    <minor>1</minor>
  </specVersion>
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <friendlyName>Tailscale Test Router</friendlyName>
    <manufacturer>Tailscale</manufacturer>
    <manufacturerURL>https://tailscale.com</manufacturerURL>
    <modelDescription>Tailscale Test Router</modelDescription>
    <modelName>Tailscale Test Router</modelName>
    <modelNumber>2.5.0-RELEASE</modelNumber>
    <modelURL>https://tailscale.com</modelURL>
    <serialNumber>1234</serialNumber>
    <UDN>uuid:1974e83b-6dc7-4635-92b3-6a85a4037294</UDN>
    <deviceList>
      <device>
	<deviceType>urn:schemas-upnp-org:device:WANDevice:1</deviceType>
	<friendlyName>WANDevice</friendlyName>
	<manufacturer>MiniUPnP</manufacturer>
	<manufacturerURL>http://miniupnp.free.fr/</manufacturerURL>
	<modelDescription>WAN Device</modelDescription>
	<modelName>WAN Device</modelName>
	<modelNumber>20990102</modelNumber>
	<modelURL>http://miniupnp.free.fr/</modelURL>
	<serialNumber>1234</serialNumber>
	<UDN>uuid:1974e83b-6dc7-4635-92b3-6a85a4037294</UDN>
	<UPC>000000000000</UPC>
	<deviceList>
	  <device>
	    <deviceType>urn:schemas-upnp-org:device:WANConnectionDevice:1</deviceType>
	    <friendlyName>WANConnectionDevice</friendlyName>
	    <manufacturer>MiniUPnP</manufacturer>
	    <manufacturerURL>http://miniupnp.free.fr/</manufacturerURL>
	    <modelDescription>MiniUPnP daemon</modelDescription>
	    <modelName>MiniUPnPd</modelName>
	    <modelNumber>20210205</modelNumber>
	    <modelURL>http://miniupnp.free.fr/</modelURL>
	    <serialNumber>1234</serialNumber>
	    <UDN>uuid:1974e83b-6dc7-4635-92b3-6a85a4037294</UDN>
	    <UPC>000000000000</UPC>
	    <serviceList>
	      <service>
		<serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
		<serviceId>urn:upnp-org:serviceId:WANIPConn1</serviceId>
		<SCPDURL>/WANIPCn.xml</SCPDURL>
		<controlURL>/ctl/IPConn</controlURL>
		<eventSubURL>/evt/IPConn</eventSubURL>
	      </service>
	    </serviceList>
	  </device>
	</deviceList>
      </device>
    </deviceList>
    <presentationURL>https://127.0.0.1/</presentationURL>
  </device>
</root>
`

const testAddPortMappingPermanentLease = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <s:Fault>
      <faultCode>s:Client</faultCode>
      <faultString>UPnPError</faultString>
      <detail>
        <UPnPError xmlns="urn:schemas-upnp-org:control-1-0">
          <errorCode>725</errorCode>
          <errorDescription>OnlyPermanentLeasesSupported</errorDescription>
        </UPnPError>
      </detail>
    </s:Fault>
  </s:Body>
</s:Envelope>
`

const testAddPortMappingResponse = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:AddPortMappingResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1"/>
  </s:Body>
</s:Envelope>
`

const testGetExternalIPAddressResponse = `<?xml version="1.0"?>
<s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/" s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/">
  <s:Body>
    <u:GetExternalIPAddressResponse xmlns:u="urn:schemas-upnp-org:service:WANIPConnection:1">
      <NewExternalIPAddress>123.123.123.123</NewExternalIPAddress>
    </u:GetExternalIPAddressResponse>
  </s:Body>
</s:Envelope>
`
