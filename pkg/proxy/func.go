package proxy

import (
	"html/template"
	"reflect"
)

func TplIntersection(lists ...interface{}) interface{} {
	var res []interface{}

	if len(lists) < 2 {
		return []struct{}{}
	}

	smallestIx := 0
	smallestLen := reflect.ValueOf(lists[0]).Len()

	for ix := range lists[1:] {
		if reflect.ValueOf(lists[ix]).Len() < smallestLen {
			smallestIx = ix
		}
	}

	smallestList := reflect.ValueOf(lists[smallestIx])

	// Because the intersection of a set of sets is, at largest,
	// the smallest subset, we can save time by first finding the
	// smallest list, and only checking the rest for those items

	for ix := 0; ix < smallestLen; ix++ {
		item := smallestList.Index(ix).Interface()
		inAll := true
		for lx, list := range lists {
			if lx == smallestLen {
				continue
			}
			l := reflect.ValueOf(list)
			found := false
			for jx := 0; jx < l.Len(); jx++ {
				item2 := l.Index(jx).Interface()
				if reflect.DeepEqual(item, item2) {
					found = true
					break
				}
			}
			if !found {
				inAll = false
				break
			}
		}
		if inAll {
			res = append(res, item)
		}
	}

	return res
}

func TplHasIntersection(lists ...interface{}) bool {
	if len(lists) < 2 {
		// This function is meant to be equivalent to
		// "does intersection return non-empty", so no lists would technically be false
		// This is also, technically, a security measure, since this function is intended
		// to be used to check for group/role membership, and this returns false if the user
		// forgets to actually supply any lists
		return false
	}

	smallestIx := 0
	smallestLen := reflect.ValueOf(lists[0]).Len()

	for ix := range lists[1:] {
		if reflect.ValueOf(lists[ix]).Len() < smallestLen {
			smallestIx = ix
		}
	}

	smallestList := reflect.ValueOf(lists[smallestIx])

	for ix := 0; ix < smallestLen; ix++ {
		item := smallestList.Index(ix).Interface()
		inAll := true
		for lx, list := range lists {
			if lx == smallestLen {
				continue
			}
			l := reflect.ValueOf(list)
			found := false
			for jx := 0; jx < l.Len(); jx++ {
				item2 := l.Index(jx).Interface()
				if reflect.DeepEqual(item, item2) {
					found = true
					break
				}
			}
			if !found {
				inAll = false
				break
			}
		}
		if inAll {
			return true
		}
	}

	return false
}

func FuncMap() template.FuncMap {
	return map[string]interface{}{
		"intersection":    TplIntersection,
		"hasIntersection": TplHasIntersection,
	}
}
