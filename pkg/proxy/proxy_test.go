package proxy_test

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"time"

	"github.com/Masterminds/sprig"
	"github.com/PuerkitoBio/goquery"
	"github.com/golang-jwt/jwt/v4"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	proxy "github.com/meln5674/mlflow-oidc-proxy/pkg/proxy"
)

const jwtSubject = "test-user"

type proxySpecState struct {
	rec *httptest.ResponseRecorder
	req *http.Request

	externalURL string

	srv *proxy.ProxyState

	method          string
	target          string
	body            io.Reader
	addJWT          bool
	addRobotCert    bool
	addRobotToken   bool
	headers         map[string]string
	claims          map[string]interface{}
	robotCert       string
	robotCertParsed *x509.Certificate
	robotToken      string
	tokenSubject    string

	tls bool

	echo *RequestEcho
}

func (p *proxySpecState) addRole(role string) {
	realmAccess, ok := p.claims["realm_access"].(map[string]interface{})
	if !ok {
		realmAccess = make(map[string]interface{})
		p.claims["realm_access"] = realmAccess
	}
	realmRoles, ok := realmAccess["roles"].([]interface{})
	if !ok {
		realmRoles = make([]interface{}, 0, 1)
		realmAccess["roles"] = realmRoles
	}
	realmRoles = append(realmRoles, role)
	realmAccess["roles"] = realmRoles
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
	if p.echo == nil {
		p.echo = new(RequestEcho)
		p.json(p.echo)
	}
	return *p.echo
}

func (p *proxySpecState) echoedRequestBodyJSON(x interface{}) {
	GinkgoHelper()
	req := p.echoedRequest()
	Expect(json.Unmarshal(req.Body, x)).To(Succeed())
}

func (p *proxySpecState) echoedRequestBodyJSONMap() map[string]interface{} {
	GinkgoHelper()
	body := make(map[string]interface{})
	p.echoedRequestBodyJSON(&body)
	return body
}

type requestWithTags struct {
	Tags []map[string]interface{} `json:"tags"`
}

func (p *proxySpecState) echoedRequestBodyJSONTags() []map[string]interface{} {
	GinkgoHelper()
	req := requestWithTags{}
	p.echoedRequestBodyJSON(&req)
	return req.Tags
}

func (p *proxySpecState) testBothRobotTypes(f func()) {
	for _, tls := range []bool{true, false} {
		msg := "using HTTP for robot certs"
		if tls {
			msg = "using HTTPS for robot certs"
		}

		func(tls bool) {
			When(msg, func() {
				BeforeEach(func() {
					p.tls = tls
				})
				f()
			})

		}(tls)
	}
}

func (p *proxySpecState) addBadTokenTests() {
	GinkgoHelper()
	When("the token is absent", func() {
		It("should return 401", func() {
			p.expectCode(http.StatusUnauthorized)
		})
	})

	When("the token is malformed", func() {
		BeforeEach(func() {
			p.headers[proxy.DefaultTokenHeader] = "asdfasdfasdf"
		})
		It("should return 400", func() {
			p.expectCode(http.StatusBadRequest)
		})
	})
	// This is only done in the HTTP version because we assume the certificate is validated by the
	// go http server that calls ServeHTTP
	When("the robot certificate is malformed", func() {
		BeforeEach(func() {
			p.addRobotCert = true
			p.robotCert = "asdfasdfasdf"
			p.robotCertParsed = &x509.Certificate{Raw: []byte("asdfasdfasdf")}
			p.tokenSubject = "robot-1"
		})
		It("should return 400", func() {
			p.expectCode(http.StatusBadRequest)
		})
	})
	p.testBothRobotTypes(func() {
		When("the robot user is not known", func() {
			BeforeEach(func() {
				p.addRobotCert = true
				p.robotCert = suiteCommonVars.RobotCertPEMs[2]
				p.robotCertParsed = suiteCommonVars.RobotCerts[2]
				p.tokenSubject = "robot-3"
			})
			It("should return 401", func() {
				p.expectCode(http.StatusUnauthorized)
			})
		})
	})
}

func (p *proxySpecState) addNoAccessTests() {
	GinkgoHelper()
	When("the user is not granted access", func() {
		BeforeEach(func() {
			p.addJWT = true
			p.tokenSubject = "testuser-2"
		})
		It("should return 403", func() {
			p.expectCode(http.StatusForbidden)
		})
	})
	p.testBothRobotTypes(func() {
		When("the robot user is not granted access", func() {
			BeforeEach(func() {
				p.addRobotToken = true
				p.robotToken = "dummy-token"
				p.tokenSubject = "robot-2"
			})
			It("should return 403", func() {
				p.expectCode(http.StatusForbidden)
			})
		})
	})
}

func testBothAPIs(p *proxySpecState, prefix, suffix string, f func(string)) {
	When("using the API", func() {
		BeforeEach(func() {
			p.target = strings.Join([]string{prefix, "api", suffix}, "/")
			GinkgoWriter.Printf("Set target to %s\n", p.target)
		})
		f("/api/" + suffix)
	})
	When("using the AJAX API", func() {
		BeforeEach(func() {
			p.target = strings.Join([]string{prefix, "ajax-api", suffix}, "/")
			GinkgoWriter.Printf("Set target to %s\n", p.target)
		})
		f(prefix + "/ajax-api/" + suffix)
	})
}

func testUserAndRobot(p *proxySpecState, f func()) {
	When("a valid JWT is present", func() {
		BeforeEach(func() {
			p.addJWT = true
			p.tokenSubject = jwtSubject
		})
		When("the user is granted access", func() {
			BeforeEach(func() {
				p.addRole("tenant-1")
			})
			f()
		})
	})
	p.testBothRobotTypes(func() {
		When("a valid robot certificate is present", func() {
			BeforeEach(func() {
				p.addRobotCert = true
			})
			When("the robot is granted access", func() {
				BeforeEach(func() {
					p.robotCert = suiteCommonVars.RobotCertPEMs[0]
					p.robotCertParsed = suiteCommonVars.RobotCerts[0]
					p.tokenSubject = "robot-1"
				})
				f()
			})
		})
	})
}

var _ = Describe("The MLFLow OIDC Proxy", func() {

	var s proxySpecState
	var cfg proxy.ProxyConfig

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

		cfg = proxy.ProxyConfig{
			HTTP: proxy.ProxyHTTPConfig{
				ExternalURL: *parsedExternalURL,
			},
			TLS: proxy.ProxyTLSConfig{
				CertFile: suiteCommonVars.ServerCertPath,
				KeyFile:  suiteCommonVars.ServerCertPath,
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
				GetSubject: proxy.Template{
					Inner: template.New("oidc.getSubject").Funcs(sprig.FuncMap()),
				},
			},
			Robots: proxy.ProxyRobotConfig{
				Robots: []proxy.Robot{
					{
						Name: "robot-1",
						Cert: proxy.CertificateFromPath{
							Raw:   "dummy-cert-1.pem",
							Inner: suiteCommonVars.RobotCerts[0],
						},
					},
					{
						Name: "robot-2",
						SecretToken: proxy.SecretTokenFromPath{
							Token: "dummy-token",
						},
					},
				},
			},
		}

		Expect(json.Unmarshal([]byte(`{ "preferred_username": "robot-1", "realm_access": { "roles": [ "tenant-1" ] } }`), &cfg.Robots.Robots[0].Token)).To(Succeed())
		Expect(json.Unmarshal([]byte(`{ "preferred_username": "robot-2", "realm_access": { "roles": [ "tenant-2" ] } }`), &cfg.Robots.Robots[1].Token)).To(Succeed())

		Expect(cfg.ApplyDefaults()).To(Succeed())

	})

	JustBeforeEach(func() {
		var err error

		var target string
		if s.tls {
			target = "https://"
		} else {
			target = "http://"
		}

		cfg.TLS.Enabled = s.tls
		cfg.TLS.Terminated = !s.tls
		target += "foo"
		target += s.target
		s.req = httptest.NewRequest(s.method, target, s.body)
		s.srv, err = proxy.NewProxy(cfg, proxy.ProxyOptions{
			Log: log.New(GinkgoWriter, "", log.LstdFlags),
		})
		Expect(err).ToNot(HaveOccurred())
		s.rec = httptest.NewRecorder()
		s.rec.Body = bytes.NewBuffer([]byte{})

		for k, v := range s.headers {
			s.req.Header.Add(k, v)
		}
		if s.addJWT {
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
				Subject:   s.tokenSubject,
			}
			claimBytes, err := json.Marshal(&stdClaims)
			Expect(err).ToNot(HaveOccurred())
			allClaims := jwt.MapClaims{}
			err = json.Unmarshal(claimBytes, &allClaims)
			Expect(err).ToNot(HaveOccurred())
			GinkgoWriter.Printf("Using claims %v\n", s.claims)
			allClaims["preferred_username"] = s.tokenSubject
			for k, v := range s.claims {
				allClaims[k] = v
			}
			token, err := jwt.NewWithClaims(tokenSigner, allClaims).SignedString(suiteCommonVars.TokenKey)
			Expect(err).ToNot(HaveOccurred())
			s.req.Header.Add(proxy.DefaultTokenHeader, token)
		}
		if s.addRobotCert {
			if s.tls {
				s.req.TLS.PeerCertificates = append(s.req.TLS.PeerCertificates, s.robotCertParsed)
				s.srv.Config.TLS.Enabled = true
			} else {
				s.req.Header.Add(proxy.DefaultCertificateHeader, url.QueryEscape(s.robotCert))
			}
		}
		if s.addRobotToken {
			s.req.Header.Add("Authorization", "Bearer "+s.robotToken)
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

		When("a valid JWT is present", func() {
			BeforeEach(func() {
				s.addJWT = true
				s.tokenSubject = jwtSubject
			})
			When("there are no authorized tenants", func() {
				It("should not produce a table of tenants", func() {
					doc := s.html()
					table := doc.Find("table")
					Expect(table.Nodes).To(HaveLen(0))
				})
			})

			When("there is one authorized tenant", func() {
				BeforeEach(func() {
					s.addRole("tenant-1")
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
					s.addRole("tenant-1")
					s.addRole("tenant-2")
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
			testUserAndRobot(&s, func() {
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
			testUserAndRobot(&s, func() {
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
			s.addNoAccessTests()
			testUserAndRobot(&s, func() {
				When("the user is granted access", func() {
					BeforeEach(func() {
						s.addRole("tenant-1")
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
			s.addNoAccessTests()
			testUserAndRobot(&s, func() {
				It("should return the upstream root", func() {
					s.expectCode(http.StatusOK)
					upstreamRequest := s.echoedRequest()
					Expect(upstreamRequest.URL.Path).To(Equal("/tenants/tenant-1/"))
				})
			})
		})
	})
	When("a missing tenant is hit", func() {
		BeforeEach(func() {
			s.method = "GET"
			s.target = "/tenants/tenant-bad"
			s.addRole("tenant-1")
		})
		s.addBadTokenTests()
		testUserAndRobot(&s, func() {
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
		s.addNoAccessTests()
		testUserAndRobot(&s, func() {
			It("should trim the static prefix from the URL", func() {
				s.expectCode(http.StatusOK)
				upstreamRequest := s.echoedRequest()
				Expect(upstreamRequest.URL.Path).To(Equal("/tenants/tenant-1/foo/bar"))
				Expect(upstreamRequest.URL.RawQuery).To(Equal("baz=qux"))
			})
		})
	})
	When("a tenant API path is hit", func() {
		BeforeEach(func() {
			s.method = "GET"
			s.target = "/tenants/tenant-1/api/foo"
		})
		s.addBadTokenTests()
		s.addNoAccessTests()
		testUserAndRobot(&s, func() {
			It("should trim the static prefix from the URL", func() {
				s.expectCode(http.StatusOK)
				upstreamRequest := s.echoedRequest()
				Expect(upstreamRequest.URL.Path).To(Equal("/api/foo"))
			})
		})
	})
	When("an unknown path is hit", func() {
		BeforeEach(func() {
			s.method = "GET"
			s.target = "/asdf"
		})
		s.addBadTokenTests()
		testUserAndRobot(&s, func() {
			It("should trim the static prefix from the URL", func() {
				s.expectCode(http.StatusNotFound)
			})
		})
	})
	When("a health endpoint hit without a token", func() {
		BeforeEach(func() {
			s.method = "GET"
			s.target = "/health"
		})
		It("should return success", func() {
			s.expectCode(http.StatusOK)
		})
	})

	type resourceTest struct {
		article      string
		name         string
		id           string
		hasDeleteTag bool
		setTagSuffix string
	}

	runs := resourceTest{
		article:      "a",
		name:         "run",
		id:           "runs",
		hasDeleteTag: true,
		setTagSuffix: "set-tag",
	}

	experiments := resourceTest{
		article:      "an",
		name:         "experiment",
		id:           "experiments",
		hasDeleteTag: false,
		setTagSuffix: "set-experiment-tag",
	}

	registeredModels := resourceTest{
		article:      "a",
		name:         "registered model",
		id:           "registered-models",
		hasDeleteTag: true,
		setTagSuffix: "set-tag",
	}

	modelVersions := resourceTest{
		article:      "a",
		name:         "model version",
		id:           "model-versions",
		hasDeleteTag: true,
		setTagSuffix: "set-tag",
	}

	tests := []resourceTest{
		experiments,
		runs,
		registeredModels,
		modelVersions,
	}

	for _, test := range tests {
		When(fmt.Sprintf("%s %s is created", test.article, test.name), func() {
			BeforeEach(func() {
				s.method = "POST"
			})
			testBothAPIs(&s, "/tenants/tenant-1", fmt.Sprintf("2.0/mlflow/%s/create", test.id), func(expectedPath string) {
				s.addBadTokenTests()
				s.addNoAccessTests()
				testUserAndRobot(&s, func() {
					cases := map[string]string{
						"the mlflow.user tag is not set": `{}`,
						"the mlflow.user tag is set":     `{"tags": [ { "key": "mlflow.user", "value": "bogus-user" } ] }`,
					}
					if test.id == "runs" {
						cases = map[string]string{
							"neither the mlflow.user tag nor user_id not set": `{}`,
							"just the mlflow.user tag is set but not user_id": `{"tags": [ { "key": "mlflow.user", "value": "bogus-user" } ] }`,
							"just user_id is set but not the mlflow.user tag": `{"user_id": "bogus-user" }`,
							"both the mlflow.user tag and user_id are set":    `{"user_id": "bogus-user", "tags": [ { "key": "mlflow.user", "value": "a-different-bogus-user" } ] }`,
						}
					}

					for name, reqBody := range cases {

						When(name, func() {
							BeforeEach(func() {
								s.body = bytes.NewBuffer([]byte(reqBody))
							})
							msg := "hit the correct API endpoint, and add set the mlflow.user tag to the token subject"
							if test.id == "runs" {
								msg = "hit the correct API endpoint, set the mlflow.user tag, and user_id field to the token subject"
							}
							It(msg, func() {
								s.expectCode(http.StatusOK)
								Expect(s.echoedRequest().URL.Path).To(Equal(expectedPath))
								if test.id == "runs" {
									Expect(s.echoedRequestBodyJSONMap()).To(HaveKeyWithValue("user_id", s.tokenSubject))
								}
								Expect(s.echoedRequestBodyJSONTags()).To(ContainElement(And(HaveKeyWithValue("key", "mlflow.user"), HaveKeyWithValue("value", s.tokenSubject))))
							})
						})
					}
				})
			})
		})
		When(fmt.Sprintf("%s %s tag is updated", test.article, test.name), func() {
			BeforeEach(func() {
				s.method = "POST"
			})
			testBothAPIs(&s, "/tenants/tenant-1", fmt.Sprintf("2.0/mlflow/%s/%s", test.id, test.setTagSuffix), func(expectedPath string) {
				s.addBadTokenTests()
				s.addNoAccessTests()
				testUserAndRobot(&s, func() {
					When("the tag is not mlflow.user", func() {
						BeforeEach(func() {
							s.body = bytes.NewBuffer([]byte(`{ "key": "bar" }`))
						})
						It("should allow it", func() {
							s.expectCode(http.StatusOK)
							Expect(s.echoedRequest().URL.Path).To(Equal(expectedPath))
							Expect(s.echoedRequestBodyJSONMap()).To(HaveKeyWithValue("key", "bar"))
						})
					})
					When("the tag is mlflow.user", func() {
						BeforeEach(func() {
							s.body = bytes.NewBuffer([]byte(`{ "key": "mlflow.user" }`))
						})
						It("should forbid it", func() {
							s.expectCode(http.StatusForbidden)
						})
					})
				})
			})
		})

		if test.hasDeleteTag {
			When(fmt.Sprintf("%s %s tag is deleted", test.article, test.name), func() {
				BeforeEach(func() {
					s.method = "POST"
				})
				testBothAPIs(&s, "/tenants/tenant-1", fmt.Sprintf("2.0/mlflow/%s/delete-tag", test.id), func(expectedPath string) {
					s.addBadTokenTests()
					s.addNoAccessTests()
					testUserAndRobot(&s, func() {
						When("the tag is not mlflow.user", func() {
							BeforeEach(func() {
								s.body = bytes.NewBuffer([]byte(`{ "key": "bar" }`))
							})
							It("should allow it", func() {
								s.expectCode(http.StatusOK)
								Expect(s.echoedRequest().URL.Path).To(Equal(expectedPath))
								Expect(s.echoedRequestBodyJSONMap()).To(HaveKeyWithValue("key", "bar"))
							})
						})
						When("the tag is mlflow.user", func() {
							BeforeEach(func() {
								s.body = bytes.NewBuffer([]byte(`{ "key": "mlflow.user" }`))
							})
							It("should forbid it", func() {
								s.expectCode(http.StatusForbidden)
							})
						})
					})
				})
			})
		}
	}
})
