package discovery

import (
	"go/ast"
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/authorization"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

// NetHTTPDiscoverer discovers endpoints in net/http applications.
type NetHTTPDiscoverer struct {
	authExtractor *authorization.NetHTTPExtractor
}

// NewNetHTTPDiscoverer creates a new NetHTTPDiscoverer.
func NewNetHTTPDiscoverer() *NetHTTPDiscoverer {
	return &NetHTTPDiscoverer{
		authExtractor: authorization.NewNetHTTPExtractor(),
	}
}

// Framework returns the framework this discoverer handles.
func (d *NetHTTPDiscoverer) Framework() models.Framework {
	return models.FrameworkNetHTTP
}

// CanHandle returns true if the source imports net/http.
func (d *NetHTTPDiscoverer) CanHandle(source *astutil.ParsedSource) bool {
	return source.HasImport("net/http")
}

// Discover finds all net/http endpoints in the source.
func (d *NetHTTPDiscoverer) Discover(source *astutil.ParsedSource) ([]*models.Endpoint, error) {
	var endpoints []*models.Endpoint

	// Find all http.HandleFunc and mux.HandleFunc calls
	ast.Inspect(source.AST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		endpoint := d.extractEndpoint(call, source)
		if endpoint != nil {
			endpoints = append(endpoints, endpoint)
		}

		return true
	})

	return endpoints, nil
}

// extractEndpoint extracts an endpoint from a route registration call.
func (d *NetHTTPDiscoverer) extractEndpoint(call *ast.CallExpr, source *astutil.ParsedSource) *models.Endpoint {
	callName := astutil.GetCallName(call)

	// Check for http.HandleFunc, http.Handle, mux.HandleFunc, mux.Handle
	isHandleFunc := strings.HasSuffix(callName, ".HandleFunc") || callName == "HandleFunc"
	isHandle := strings.HasSuffix(callName, ".Handle") || callName == "Handle"

	if !isHandleFunc && !isHandle {
		return nil
	}

	if len(call.Args) < 2 {
		return nil
	}

	route := astutil.GetStringValue(call.Args[0])
	if route == "" {
		return nil
	}

	// Extract handler name
	handlerName := d.extractHandlerName(call.Args[1])

	// net/http handlers typically handle all methods unless they check r.Method
	// We default to all methods since we can't determine statically
	methods := []models.HTTPMethod{
		models.MethodGET,
		models.MethodPOST,
		models.MethodPUT,
		models.MethodDELETE,
		models.MethodPATCH,
		models.MethodHEAD,
		models.MethodOPTIONS,
	}

	// Extract authorization info
	auth := d.authExtractor.Extract(nil, source)

	endpoint := &models.Endpoint{
		Route:         route,
		Methods:       methods,
		FilePath:      source.FilePath,
		LineNumber:    astutil.GetLineNumber(source.FileSet, call),
		Framework:     models.FrameworkNetHTTP,
		EndpointType:  models.EndpointTypeFunction,
		FunctionName:  handlerName,
		Authorization: auth,
	}

	return endpoint
}

// extractHandlerName extracts the function name from a handler argument.
func (d *NetHTTPDiscoverer) extractHandlerName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if ident, ok := e.X.(*ast.Ident); ok {
			return ident.Name + "." + e.Sel.Name
		}
	case *ast.FuncLit:
		return "<anonymous>"
	case *ast.CallExpr:
		return astutil.GetCallName(e)
	}
	return ""
}
