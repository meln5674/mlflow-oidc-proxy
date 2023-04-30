package proxy_test

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/PuerkitoBio/goquery"
	"github.com/golang-jwt/jwt/v4"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	proxy "github.com/meln5674/mlflow-oidc-proxy/pkg/proxy"
)

type proxySpecState struct {
	rec *httptest.ResponseRecorder
	req *http.Request

	externalURL string

	srv *proxy.ProxyState

	method    string
	target    string
	body      io.Reader
	skipToken bool
	headers   map[string]string
	claims    map[string]interface{}
}

func (p *proxySpecState) expectCode(code int) {
	GinkgoHelper()
	Expect(p.rec.Code).To(Equal(code))
}

func (p *proxySpecState) expectRedirect(code int, location string) {
	GinkgoHelper()
	p.expectCode(code)
	Expect(p.rec.Result().Location()).To(WithTransform(func(u *url.URL) string { return u.String() }, Equal(location)))
}

func (p *proxySpecState) debugBody() io.Reader {
	return io.TeeReader(p.rec.Body, GinkgoWriter)
}

func (p *proxySpecState) html() *goquery.Document {
	GinkgoHelper()
	doc, err := goquery.NewDocumentFromReader(p.debugBody())
	Expect(err).ToNot(HaveOccurred())
	return doc
}

func (p *proxySpecState) json(x interface{}) {
	GinkgoHelper()
	Expect(json.NewDecoder(p.debugBody()).Decode(x)).To(Succeed())
}

func (p *proxySpecState) echoedRequest() RequestEcho {
	GinkgoHelper()
	req := RequestEcho{}
	p.json(&req)
	return req
}

func (p *proxySpecState) addBadTokenTests() {
	GinkgoHelper()
	When("the token is absent", func() {
		BeforeEach(func() {
			p.skipToken = true
		})
		It("should return 401", func() {
			p.expectCode(http.StatusUnauthorized)
		})
	})

	When("the token is malformed", func() {
		BeforeEach(func() {
			p.skipToken = true
			p.headers[proxy.DefaultAccessTokenHeader] = "asdfasdfasdf"
		})
		It("should return 400", func() {
			p.expectCode(http.StatusBadRequest)
		})
	})
}

func (p *proxySpecState) addNoAccessTests() {
	When("the user is not granted access", func() {
		It("should return 403", func() {
			p.expectCode(http.StatusForbidden)
		})
	})
}

var _ = Describe("The MLFLow OIDC Proxy", func() {

	var s proxySpecState

	BeforeEach(func() {
		s = proxySpecState{
			externalURL: "https://some.external.url",
			headers:     make(map[string]string),
			claims:      make(map[string]interface{}),
		}
		parsedExternalURL, err := new(proxy.URL).Parse(s.externalURL)
		Expect(err).ToNot(HaveOccurred())
		parsedTenant1URL, err := new(proxy.URL).Parse(fakeMLFlow1.URL)
		Expect(err).ToNot(HaveOccurred())
		parsedTenant2URL, err := new(proxy.URL).Parse(fakeMLFlow2.URL)
		Expect(err).ToNot(HaveOccurred())

		cfg := proxy.ProxyConfig{
			HTTP: proxy.ProxyHTTPConfig{
				ExternalURL: *parsedExternalURL,
			},
			MLFlow: proxy.ProxyMLFlowConfig{
				Tenants: []proxy.ProxyMLFlowTenant{
					{
						ID:       "tenant-1",
						Name:     "Tenant 1",
						Upstream: *parsedTenant1URL,
					},
					{
						ID:       "tenant-2",
						Name:     "Tenant 2",
						Upstream: *parsedTenant2URL,
					},
				},
			},
			OIDC: proxy.ProxyOIDCConfig{
				Policy: proxy.Template{
					Inner: template.New("oidc.policy").Funcs(sprig.FuncMap()),
				},
			},
		}
		Expect(cfg.ApplyDefaults()).To(Succeed())

		opts := proxy.ProxyOptions{
			Log: log.New(GinkgoWriter, "", log.LstdFlags),
		}

		s.srv, err = proxy.NewProxy(cfg, opts)
		Expect(err).ToNot(HaveOccurred())
		s.rec = httptest.NewRecorder()
		s.rec.Body = bytes.NewBuffer([]byte{})

	})

	JustBeforeEach(func() {
		s.req = httptest.NewRequest(s.method, s.target, s.body)
		for k, v := range s.headers {
			s.req.Header.Add(k, v)
		}
		if !s.skipToken {
			now := time.Now()
			exp := now.Add(1 * time.Hour)
			id, err := rand.Int(rand.Reader, big.NewInt(1<<62))
			Expect(err).ToNot(HaveOccurred())
			stdClaims := jwt.StandardClaims{
				Audience:  "mlflow",
				ExpiresAt: exp.Unix(),
				Id:        fmt.Sprintf("%d", id.Int64()),
				IssuedAt:  now.Unix(),
				Issuer:    "test",
				NotBefore: now.Unix(),
				Subject:   "test-user",
			}
			claimBytes, err := json.Marshal(&stdClaims)
			Expect(err).ToNot(HaveOccurred())
			allClaims := jwt.MapClaims{}
			err = json.Unmarshal(claimBytes, &allClaims)
			Expect(err).ToNot(HaveOccurred())
			GinkgoWriter.Printf("Using claims %v\n", s.claims)
			for k, v := range s.claims {
				allClaims[k] = v
			}
			token, err := jwt.NewWithClaims(tokenSigner, allClaims).SignedString(tokenKey)
			Expect(err).ToNot(HaveOccurred())
			s.req.Header.Add(proxy.DefaultAccessTokenHeader, token)
		}

		GinkgoWriter.Printf("Executing request\n")
		s.srv.ServeHTTP(s.rec, s.req)
	})

	When("the root url is hit", func() {
		BeforeEach(func() {
			s.method = "GET"
			s.target = "/"
		})

		s.addBadTokenTests()

		When("a valid token is present", func() {
			When("there are no authorized tenants", func() {
				It("should not produce a table of tenants", func() {
					doc := s.html()
					table := doc.Find("table")
					Expect(table.Nodes).To(HaveLen(0))
				})
			})

			When("there is one authorized tenant", func() {
				BeforeEach(func() {
					s.claims["realm_access"] = map[string]interface{}{
						"roles": []interface{}{
							"tenant-1",
						},
					}
				})
				It("should return a table with that tenant's link", func() {
					s.expectCode(http.StatusOK)
					doc := s.html()

					table := doc.Find("table")
					Expect(table.Nodes).To(HaveLen(1))
					tableRows := doc.Find("table tr")
					Expect(tableRows.Nodes).To(HaveLen(2))
					tenantRow := doc.Find("table > tbody > tr#tenant-1 > td > a")
					Expect(tenantRow.Nodes).To(HaveLen(1))
					Expect(tenantRow.Nodes[0].Attr).To(HaveLen(1))
					Expect(tenantRow.Nodes[0].Attr[0].Key).To(Equal("href"))
					Expect(tenantRow.Nodes[0].Attr[0].Val).To(Equal(s.externalURL + "/tenants/tenant-1/"))
				})
			})
			When("there are two authorized tenants", func() {
				BeforeEach(func() {
					s.claims["realm_access"] = map[string]interface{}{
						"roles": []interface{}{
							"tenant-1",
							"tenant-2",
						},
					}
				})
				It("should return a table with both those tenants' links", func() {
					s.expectCode(http.StatusOK)
					doc := s.html()

					table := doc.Find("table")
					Expect(table.Nodes).To(HaveLen(1))
					tableRows := doc.Find("table tr")
					Expect(tableRows.Nodes).To(HaveLen(3))
					for _, ix := range []int{1, 2} {
						tenantRow := doc.Find(fmt.Sprintf("table > tbody > tr#tenant-%d > td > a", ix))
						Expect(tenantRow.Nodes).To(HaveLen(1))
						Expect(tenantRow.Nodes[0].Attr).To(HaveLen(1))
						Expect(tenantRow.Nodes[0].Attr[0].Key).To(Equal("href"))
						Expect(tenantRow.Nodes[0].Attr[0].Val).To(Equal(s.externalURL + fmt.Sprintf("/tenants/tenant-%d/", ix)))
					}
				})
			})
		})
	})

	When("the tenants prefix is hit", func() {
		When("there is a trailing slash", func() {
			BeforeEach(func() {
				s.method = "GET"
				s.target = "/tenants"
			})
			s.addBadTokenTests()
			When("a valid token is present", func() {
				It("should redirect the root url", func() {
					s.expectRedirect(http.StatusPermanentRedirect, s.externalURL+"/")
				})
			})
		})

		When("there isn't a trailing slash", func() {
			BeforeEach(func() {
				s.target = "/tenants/"
			})
			s.addBadTokenTests()
			When("a valid token is present", func() {
				It("should redirect the root url", func() {
					s.expectRedirect(http.StatusPermanentRedirect, s.externalURL+"/")
				})
			})
		})
	})

	When("a tenant root is hit", func() {
		When("there isn't a trailing slash", func() {
			BeforeEach(func() {
				s.method = "GET"
				s.target = "/tenants/tenant-1"
			})
			s.addBadTokenTests()
			When("a valid token is present", func() {
				s.addNoAccessTests()
				When("the user is granted access", func() {
					BeforeEach(func() {
						s.claims["realm_access"] = map[string]interface{}{
							"roles": []interface{}{
								"tenant-1",
							},
						}
					})
					It("should redirect to the tenant root", func() {
						s.expectRedirect(http.StatusPermanentRedirect, s.externalURL+"/tenants/tenant-1/")
					})
				})
			})
		})
		When("there is a trailing slash", func() {
			BeforeEach(func() {
				s.method = "GET"
				s.target = "/tenants/tenant-1/"
			})
			s.addBadTokenTests()
			When("a valid token is present", func() {
				s.addNoAccessTests()
				When("the user is granted access", func() {
					BeforeEach(func() {
						s.claims["realm_access"] = map[string]interface{}{
							"roles": []interface{}{
								"tenant-1",
							},
						}
					})
					It("should return the upstream root", func() {
						s.expectCode(http.StatusOK)
						upstreamRequest := s.echoedRequest()
						Expect(upstreamRequest.URL.Path).To(Equal("/tenants/tenant-1/"))
					})
				})
			})
		})
	})
	When("a missing tenant is hit", func() {
		BeforeEach(func() {
			s.method = "GET"
			s.target = "/tenants/tenant-bad"
			s.claims["realm_access"] = map[string]interface{}{
				"roles": []interface{}{
					"tenant-1",
				},
			}
		})
		s.addBadTokenTests()
		When("a valid token is present", func() {
			It("should return not found", func() {
				s.expectCode(http.StatusNotFound)
			})
		})
	})
	When("a tenant non-API path is hit", func() {
		BeforeEach(func() {
			s.method = "GET"
			s.target = "/tenants/tenant-1/foo/bar?baz=qux"
		})
		s.addBadTokenTests()
		When("a valid token is present", func() {
			s.addNoAccessTests()
			When("the user is granted access", func() {
				BeforeEach(func() {
					s.claims["realm_access"] = map[string]interface{}{
						"roles": []interface{}{
							"tenant-1",
						},
					}
				})
				It("should trim the static prefix from the URL", func() {
					s.expectCode(http.StatusOK)
					upstreamRequest := s.echoedRequest()
					Expect(upstreamRequest.URL.Path).To(Equal("/tenants/tenant-1/foo/bar"))
					Expect(upstreamRequest.URL.RawQuery).To(Equal("baz=qux"))
				})
			})
		})
	})
	When("a tenant API path is hit", func() {
		BeforeEach(func() {
			s.method = "GET"
			s.target = "/tenants/tenant-1/api/foo"
		})
		s.addBadTokenTests()
		When("a valid token is present", func() {
			s.addNoAccessTests()
			When("the user is granted access", func() {
				BeforeEach(func() {
					s.claims["realm_access"] = map[string]interface{}{
						"roles": []interface{}{
							"tenant-1",
						},
					}
				})
				It("should trim the static prefix from the URL", func() {
					s.expectCode(http.StatusOK)
					upstreamRequest := s.echoedRequest()
					Expect(upstreamRequest.URL.Path).To(Equal("/api/foo"))
				})
			})
		})
	})
	When("an unknown path is hit", func() {
		BeforeEach(func() {
			s.method = "GET"
			s.target = "/asdf"
		})
		s.addBadTokenTests()
		When("a valid token is present", func() {
			It("should trim the static prefix from the URL", func() {
				s.expectCode(http.StatusNotFound)
			})
		})
	})
	When("a health endpoint hit without a token", func() {
		BeforeEach(func() {
			s.method = "GET"
			s.target = "/health"
			s.skipToken = true
		})
		It("should return success", func() {
			s.expectCode(http.StatusOK)
		})
	})
})
