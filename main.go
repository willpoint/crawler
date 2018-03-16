package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/html"
)

// frontier dispenses URLs according to its policies
// holds a list of seen URLs and a never-before-seen URLs
type frontier struct {
	seen   []*visitable
	nbs    []*visitable // treated as a queue
	filter func(f *frontier, uri string) (*url.URL, error)
	lk     sync.Mutex
}

func main() {

	address := flag.String("seed", "", "URL(s) to crawl - multiple URLs to be joined by an ampersand(&)")
	flag.Parse()

	var seed []string
	var iv []*visitable

	if strings.Contains(*address, "&") {
		seed = strings.Split(*address, "&")
	}
	seed = append(seed, *address)

	for _, s := range seed {
		u, err := url.Parse(s)
		if err != nil {
			continue // move on
		}
		iv = append(iv, &visitable{uri: u})
	}

	frnt := &frontier{
		nbs:    iv,
		filter: urlFilter,
	}

	ctx, timeout := context.WithTimeout(context.Background(), 15*time.Second)
	defer timeout()
	go crawl(ctx, frnt)
	select {
	case <-ctx.Done():
		for _, i := range frnt.seen {
			fmt.Println(i.uri.String())
		}
	}
}

func crawl(ctx context.Context, frnt *frontier) {
	for {
		select {
		case <-ctx.Done():
			return
		case url := <-frnt.Eligible(ctx):
			ft, err := newFetcher(config{Address: url})
			if err != nil {
				continue // move on
			}
			_, body, err := ft.Do(ctx)
			if err != nil {
				frnt.MarkSeen(url, false)
			}
			r := bytes.NewReader(body)
			links, err := linkExtractor(r)
			if err != nil {
				frnt.MarkSeen(url, false)
			}
			frnt.Add(links...)
			frnt.Dequeue()
			frnt.MarkSeen(url, true)

		}
	}
}

func display(s []*visitable) {
	for _, v := range s {
		fmt.Printf("%s ", v.uri.String())
	}
}

// TODO(uz) - implement a cache for robots.txt exclusion mechanism
// robotsCache keeps a record exclusion URLs from visiting server
// the key are a hash of the host
type robotsCache map[string][]string

// Sanitize cache is applies a policy to clear the cache of robots.txt
// data from sites - using time visited to free memory
func (rc *robotsCache) Sanitize() {
	// implementation ...
}

// visitable represents a URL and a flag indicating
// that the page represented by the uri has been downloaded
type visitable struct {
	uri       *url.URL
	visited   bool
	success   bool
	visitedAt time.Time
}

// Add adds to the frontier's list of unseen visitables
// must be safe for concurrent use by multiple goroutines
func (f *frontier) Add(uri ...string) {
	for _, i := range uri {
		u, err := f.filter(f, i)
		if err != nil {
			continue // do nothing
		}
		f.lk.Lock()
		f.nbs = append(f.nbs, &visitable{uri: u})
		f.lk.Unlock()
	}
}

// Eligible is called to retrieve the next visitable
func (f *frontier) Eligible(ctx context.Context) <-chan string {
	uri := make(chan string)
	go func() {
		defer close(uri)
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			if len(f.nbs) == 0 {
				continue
			}
			uri <- f.nbs[0].uri.String()
		}
	}()
	return uri
}

// Dequeue remove the first visitable from the queue of nbs
func (f *frontier) Dequeue() {
	f.lk.Lock()
	defer f.lk.Unlock()
	if len(f.nbs) == 0 {
		return
	}
	f.nbs = f.nbs[1:]
}

// MarkSeen adds the uri visited to the frontier's list of seen
func (f *frontier) MarkSeen(uri string, success bool) {
	u, err := url.Parse(uri)
	if err != nil {
		return
	}
	f.lk.Lock()
	// and add to seen
	f.seen = append(f.seen, &visitable{
		uri:       u,
		visited:   true,
		success:   success,
		visitedAt: time.Now(),
	})
	f.lk.Unlock()
}

// Fetcher represents the type that connects to the webserver ...
type Fetcher interface {
	Do(context.Context) (*http.Response, []byte, error)
	Save([]byte)
}

type fetcher struct {
	address *url.URL
	client  http.Client
}

// Save method helps to implement the Fetch interface
// may or may not save the data in a repository
// TODO(uz) make []byte be a datastore interface
// that can Save([]byte)error the data
func (f *fetcher) Save(data []byte) {
	fmt.Println(string(data))
}

// urlFilter type returns a list of url strings
// filtered based on some internal rules
// it also ensures no URLs previously discovered so should be succeed
// so it can be moved to the never-before-seen URLs
func urlFilter(f *frontier, uri string) (*url.URL, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, err
	}
	// TODO(uz) - add other rules to filter url
	// eg. checking a blacklist of URLs
	for _, sn := range f.seen {
		if sn.uri.String() == uri {
			return nil, errors.New("error: uri has been previously seen")
		}
	}
	// check other rules before returning the url
	return u, nil
}

// linkExtractor extracts hyperlinks from the downloaded page
func linkExtractor(body io.Reader) (links []string, err error) {
	doc, err := html.Parse(body)
	if err != nil {
		return nil, err
	}
	emitLink := func(link string) {
		links = append(links, link)
	}
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == "a" {
			attrs := n.Attr
			for _, a := range attrs {
				if a.Key == "href" {
					emitLink(a.Val)
				}
			}
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)
	return
}

// Do method helps fetcher implement the Fetcher interface
// TODO(uz) implement a check for robots.txt for exclusion rules
// before download
func (f *fetcher) Do(ctx context.Context) (*http.Response, []byte, error) {

	req, err := http.NewRequest("GET", f.address.String(), nil)

	if err != nil {
		return nil, nil, err
	}

	if ctx != nil {
		req = req.WithContext(ctx)
	}

	resp, err := f.client.Do(req)
	defer func() {
		if resp != nil {
			resp.Body.Close()
		}
	}()

	if err != nil {
		return nil, nil, err
	}

	var body []byte
	done := make(chan struct{})
	// a seperate go routine to read resp into body
	go func() {
		body, err = ioutil.ReadAll(resp.Body)
		close(done)
	}()

	select {
	case <-ctx.Done():
		<-done
		if err == nil {
			err = ctx.Err()
		}
	case <-done:
	}
	return resp, body, err
}

func newFetcher(cfg config) (Fetcher, error) {
	u, err := url.Parse(cfg.Address)
	if err != nil {
		return nil, err
	}
	return &fetcher{
		address: u,
		client:  http.Client{Transport: cfg.roundTripper()},
	}, nil
}

type config struct {
	Address      string
	RoundTripper http.RoundTripper
}

func (cfg *config) roundTripper() http.RoundTripper {
	if cfg.RoundTripper == nil {
		return defaultRoundTripper
	}
	return cfg.RoundTripper
}

// defaultRoundTripper used to drive http requests
var defaultRoundTripper http.RoundTripper = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true, // connect to both ipv4 & ipv6 ip addresses
	}).DialContext,
	MaxIdleConns:          100,
	IdleConnTimeout:       10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
}
