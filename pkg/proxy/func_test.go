package proxy_test

import (
	"html/template"
	"strings"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"

	"github.com/meln5674/mlflow-oidc-proxy/pkg/proxy"
)

var _ = Describe("Intersection", func() {
	When("No lists are provided", func() {
		It("returns an empty list", func() {
			Expect(proxy.TplIntersection()).To(BeEmpty())
		})
	})

	When("An single empty list is provided", func() {
		It("returns an empty list", func() {
			Expect(proxy.TplIntersection([]string{})).To(BeEmpty())
		})
	})

	When("An single non-empty list is provided", func() {
		It("returns an empty list", func() {
			Expect(proxy.TplIntersection([]string{"1", "2", "3"})).To(BeEmpty())
		})
	})

	When("Two lists with overlap are provided", func() {
		It("returns the overlap", func() {
			Expect(proxy.TplIntersection([]string{"1", "2", "3"}, []string{"2", "3", "4"})).To(HaveExactElements("2", "3"))
		})
	})

	When("Two lists with no overlap are provided", func() {
		It("returns an empty list", func() {
			Expect(proxy.TplIntersection([]string{"1", "2", "3"}, []string{"4", "5", "6"})).To(BeEmpty())
		})
	})

	When("A list and a subset are provided", func() {
		It("returns the subset", func() {
			Expect(proxy.TplIntersection([]string{"1", "2", "3"}, []string{"1", "2"})).To(HaveExactElements("1", "2"))
		})
	})

	When("Three lists with overlap are provided", func() {
		It("returns the overlap", func() {
			Expect(proxy.TplIntersection([]string{"1", "2", "3"}, []string{"2", "3", "4"}, []string{"3", "4", "5"})).To(HaveExactElements("3"))
		})
	})

	When("Three lists with no overlap are provided", func() {
		It("returns an empty list", func() {
			Expect(proxy.TplIntersection([]string{"1", "2", "3"}, []string{"4", "5", "6"}, []string{"7", "8", "9"})).To(BeEmpty())
		})
	})

})

var _ = Describe("HasIntersection", func() {
	When("No lists are provided", func() {
		It("returns an empty list", func() {
			Expect(proxy.TplHasIntersection()).To(BeFalse())
		})
	})

	When("An single empty list is provided", func() {
		It("returns an empty list", func() {
			Expect(proxy.TplHasIntersection([]string{})).To(BeFalse())
		})
	})

	When("An single non-empty list is provided", func() {
		It("returns an empty list", func() {
			Expect(proxy.TplHasIntersection([]string{"1", "2", "3"})).To(BeFalse())
		})
	})

	When("Two lists with overlap are provided", func() {
		It("returns the overlap", func() {
			Expect(proxy.TplHasIntersection([]string{"1", "2", "3"}, []string{"2", "3", "4"})).To(BeTrue())
		})
	})

	When("Two lists with no overlap are provided", func() {
		It("returns an empty list", func() {
			Expect(proxy.TplHasIntersection([]string{"1", "2", "3"}, []string{"4", "5", "6"})).To(BeFalse())
		})
	})

	When("A list and a subset are provided", func() {
		It("returns the subset", func() {
			Expect(proxy.TplHasIntersection([]string{"1", "2", "3"}, []string{"1", "2"})).To(BeTrue())
		})
	})

	When("Three lists with overlap are provided", func() {
		It("returns the overlap", func() {
			Expect(proxy.TplHasIntersection([]string{"1", "2", "3"}, []string{"2", "3", "4"}, []string{"3", "4", "5"})).To(BeTrue())
		})
	})

	When("Three lists with no overlap are provided", func() {
		It("returns an empty list", func() {
			Expect(proxy.TplHasIntersection([]string{"1", "2", "3"}, []string{"4", "5", "6"}, []string{"7", "8", "9"})).To(BeFalse())
		})
	})

})

var _ = Describe("FuncMap", func() {
	It("Should provide the intersection function", func() {
		out := strings.Builder{}
		tpl, err := template.New("test").Funcs(proxy.FuncMap()).Parse(`{{- range $x := intersection .X .Y }}{{ $x }} {{ end -}}`)
		Expect(err).ToNot(HaveOccurred())
		data := map[string]interface{}{
			"X": []string{"1", "2", "3"},
			"Y": []string{"2", "3", "4"},
		}
		Expect(tpl.Execute(&out, data)).To(Succeed())
		Expect(out.String()).To(Equal("2 3 "))
	})

	It("Should provide the hasIntersection function", func() {
		out := strings.Builder{}
		tpl, err := template.New("test").Funcs(proxy.FuncMap()).Parse(`{{- hasIntersection .X .Y }}`)
		Expect(err).ToNot(HaveOccurred())
		data := map[string]interface{}{
			"X": []string{"1", "2", "3"},
			"Y": []string{"2", "3", "4"},
		}
		Expect(tpl.Execute(&out, data)).To(Succeed())
		Expect(out.String()).To(Equal("true"))
	})

})
