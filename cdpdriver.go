package cdpdriver

import (
	"context"
	"crypto/sha1"
	"encoding/gob"
	"encoding/hex"
	"errors"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/chromedp/chromedp"
	"github.com/gocolly/colly"
)

type CDPDriver struct {
	cdp        *chromedp.CDP
	limitRules []*colly.LimitRule
	lock       *sync.RWMutex
	timeout    time.Duration
}

func NewDriver() *CDPDriver {
	return &CDPDriver{lock: &sync.RWMutex{}}
}

func (c *CDPDriver) Init(jar http.CookieJar) {
	cdp, err := chromedp.New(context.Background())
	if err != nil {
		panic(err)
	}

	c.cdp = cdp
}

func (c *CDPDriver) GetMatchingRule(domain string) *colly.LimitRule {
	if c.limitRules == nil {
		return nil
	}
	c.lock.RLock()
	defer c.lock.RUnlock()
	for _, r := range c.limitRules {
		if r.Match(domain) {
			return r
		}
	}
	return nil
}

func (c *CDPDriver) Cache(request *http.Request, bodySize int, cacheDir string) (*colly.Response, error) {
	if cacheDir == "" || request.Method != "GET" {
		return c.Do(request, bodySize)
	}
	sum := sha1.Sum([]byte(request.URL.String()))
	hash := hex.EncodeToString(sum[:])
	dir := path.Join(cacheDir, hash[:2])
	filename := path.Join(dir, hash)
	if file, err := os.Open(filename); err == nil {
		resp := new(colly.Response)
		err := gob.NewDecoder(file).Decode(resp)
		file.Close()
		if resp.StatusCode < 500 {
			return resp, err
		}
	}
	resp, err := c.Do(request, bodySize)
	if err != nil || resp.StatusCode >= 500 {
		return resp, err
	}
	if _, err := os.Stat(dir); err != nil {
		if err := os.MkdirAll(dir, 0750); err != nil {
			return resp, err
		}
	}
	file, err := os.Create(filename + "~")
	if err != nil {
		return resp, err
	}
	if err := gob.NewEncoder(file).Encode(resp); err != nil {
		file.Close()
		return resp, err
	}
	file.Close()
	return resp, os.Rename(filename+"~", filename)
}

func (c *CDPDriver) Do(request *http.Request, bodySize int) (*colly.Response, error) {
	r := c.GetMatchingRule(request.URL.Host)
	if r != nil {
		r.WaitChan <- true
		defer func(r *colly.LimitRule) {
			randomDelay := time.Duration(0)
			if r.RandomDelay != 0 {
				randomDelay = time.Duration(rand.Intn(int(r.RandomDelay)))
			}
			time.Sleep(r.Delay + randomDelay)
			<-r.WaitChan
		}(r)
	}

	if strings.ToUpper(request.Method) != "GET" {
		return nil, errors.New("CDPDriver only support GET requests")
	}

	ctx := context.Background()
	u := request.URL

	err := c.cdp.Run(ctx, chromedp.Navigate(u.String()))

	if err != nil {
		return nil, err
	}
	err = c.cdp.Run(ctx, chromedp.WaitReady("h1#firstHeading"))
	ctx = context.Background()
	var body string

	c.cdp.Run(ctx, chromedp.OuterHTML("html", &body))
	if err != nil {
		return nil, err
	}
	return &colly.Response{
		StatusCode: 200,
		Body:       []byte(body),
		Headers:    &http.Header{"Content-Type": []string{"html"}},
	}, nil
}

func (c *CDPDriver) Limit(rule *colly.LimitRule) error {
	c.lock.Lock()
	if c.limitRules == nil {
		c.limitRules = make([]*colly.LimitRule, 0, 8)
	}
	c.limitRules = append(c.limitRules, rule)
	c.lock.Unlock()
	return rule.Init()
}

func (c *CDPDriver) Limits(rules []*colly.LimitRule) error {
	for _, r := range rules {
		if err := c.Limit(r); err != nil {
			return err
		}
	}
	return nil
}

func (c *CDPDriver) Jar(j http.CookieJar) {

}

func (c *CDPDriver) GetJar() http.CookieJar {
	return nil
}

func (c *CDPDriver) Transport(t http.RoundTripper) {

}

func (c *CDPDriver) Timeout(t time.Duration) {
	c.timeout = t
}

func (c *CDPDriver) GetTimeout() time.Duration {
	return c.timeout
}

func (c *CDPDriver) Proxy(pf colly.ProxyFunc) {

}

func (c *CDPDriver) SetCookies(url *url.URL, cookies []*http.Cookie) error {
	return nil
}

func (c *CDPDriver) Cookies(url *url.URL) []*http.Cookie {
	return nil
}

func (c *CDPDriver) CheckRedirect(f func(req *http.Request, via []*http.Request) error) {

}
