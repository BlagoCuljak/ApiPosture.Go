package discovery

import (
	"go/ast"
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/authorization"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

const echoImport = "github.com/labstack/echo/v4"

// echoRouteMethods maps Echo method names to HTTP methods.
var echoRouteMethods = map[string]models.HTTPMethod{
	"GET":     models.MethodGET,
	"POST":    models.MethodPOST,
	"PUT":     models.MethodPUT,
	"DELETE":  models.MethodDELETE,
	"PATCH":   models.MethodPATCH,
	"HEAD":    models.MethodHEAD,
	"OPTIONS": models.MethodOPTIONS,
}

// EchoDiscoverer discovers endpoints in Echo applications.
type EchoDiscoverer struct {
	authExtractor *authorization.EchoExtractor
}

// NewEchoDiscoverer creates a new EchoDiscoverer.
func NewEchoDiscoverer() *EchoDiscoverer {
	return &EchoDiscoverer{
		authExtractor: authorization.NewEchoExtractor(),
	}
}

// Framework returns the framework this discoverer handles.
func (d *EchoDiscoverer) Framework() models.Framework {
	return models.FrameworkEcho
}

// CanHandle returns true if the source imports Echo.
func (d *EchoDiscoverer) CanHandle(source *astutil.ParsedSource) bool {
	return source.HasImport(echoImport) || source.HasImportPrefix("github.com/labstack/echo")
}

// Discover finds all Echo endpoints in the source.
func (d *EchoDiscoverer) Discover(source *astutil.ParsedSource) ([]*models.Endpoint, error) {
	var endpoints []*models.Endpoint

	// Find router groups
	groups := d.findGroups(source)

	// Find all route registrations
	ast.Inspect(source.AST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		endpoint := d.extractEndpoint(call, source, groups)
		if endpoint != nil {
			endpoints = append(endpoints, endpoint)
		}

		return true
	})

	return endpoints, nil
}

// EchoGroupInfo stores information about an Echo router group.
type EchoGroupInfo struct {
	Prefix     string
	Middleware []string
	VarName    string
}

// findGroups finds all Echo Group() calls and their prefixes/middleware.
func (d *EchoDiscoverer) findGroups(source *astutil.ParsedSource) map[string]*EchoGroupInfo {
	groups := make(map[string]*EchoGroupInfo)

	ast.Inspect(source.AST, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok {
			return true
		}

		if len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			return true
		}

		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			return true
		}

		callName := astutil.GetCallName(call)
		if !strings.HasSuffix(callName, ".Group") {
			return true
		}

		ident, ok := assign.Lhs[0].(*ast.Ident)
		if !ok {
			return true
		}

		group := &EchoGroupInfo{
			VarName: ident.Name,
		}

		// Extract prefix
		if len(call.Args) > 0 {
			group.Prefix = astutil.GetStringValue(call.Args[0])
		}

		// Extract middleware (rest of the arguments)
		for i := 1; i < len(call.Args); i++ {
			if fn := d.extractHandlerName(call.Args[i]); fn != "" {
				group.Middleware = append(group.Middleware, fn)
			}
		}

		groups[ident.Name] = group
		return true
	})

	return groups
}

// extractEndpoint extracts an endpoint from a route registration call.
func (d *EchoDiscoverer) extractEndpoint(call *ast.CallExpr, source *astutil.ParsedSource, groups map[string]*EchoGroupInfo) *models.Endpoint {
	callName := astutil.GetCallName(call)
	parts := strings.Split(callName, ".")

	if len(parts) < 2 {
		return nil
	}

	receiverVar := parts[0]
	methodName := parts[1]

	// Check if this is a route method
	httpMethod, isRoute := echoRouteMethods[methodName]
	if !isRoute {
		// Check for Add() which takes method as first argument
		if methodName == "Add" && len(call.Args) >= 3 {
			methodStr := astutil.GetStringValue(call.Args[0])
			httpMethod, isRoute = echoRouteMethods[methodStr]
			if !isRoute {
				return nil
			}
			// Shift args for Add case
			call.Args = call.Args[1:]
		} else if methodName == "Any" {
			// Any() matches all methods
			return d.createEndpoint(call, source, groups, receiverVar,
				[]models.HTTPMethod{models.MethodGET, models.MethodPOST, models.MethodPUT,
					models.MethodDELETE, models.MethodPATCH, models.MethodHEAD, models.MethodOPTIONS})
		} else {
			return nil
		}
	}

	return d.createEndpoint(call, source, groups, receiverVar, []models.HTTPMethod{httpMethod})
}

// createEndpoint creates an Endpoint from a route call.
func (d *EchoDiscoverer) createEndpoint(call *ast.CallExpr, source *astutil.ParsedSource, groups map[string]*EchoGroupInfo, receiverVar string, methods []models.HTTPMethod) *models.Endpoint {
	if len(call.Args) < 2 {
		return nil
	}

	route := astutil.GetStringValue(call.Args[0])
	if route == "" {
		return nil
	}

	// Extract handler name (second argument)
	handlerName := d.extractHandlerName(call.Args[1])

	// Extract middleware (rest of arguments)
	var middleware []string
	for i := 2; i < len(call.Args); i++ {
		if fn := d.extractHandlerName(call.Args[i]); fn != "" {
			middleware = append(middleware, fn)
		}
	}

	// Determine group prefix and middleware
	prefix := ""
	var groupMiddleware []string
	if group, ok := groups[receiverVar]; ok {
		prefix = group.Prefix
		groupMiddleware = group.Middleware
	}

	// Extract authorization info
	allMiddleware := append(groupMiddleware, middleware...)
	auth := d.authExtractor.Extract(allMiddleware, source)

	endpoint := &models.Endpoint{
		Route:         route,
		Methods:       methods,
		FilePath:      source.FilePath,
		LineNumber:    astutil.GetLineNumber(source.FileSet, call),
		Framework:     models.FrameworkEcho,
		EndpointType:  models.EndpointTypeFunction,
		FunctionName:  handlerName,
		Authorization: auth,
		RouterPrefix:  prefix,
	}

	return endpoint
}

// extractHandlerName extracts the function name from a handler argument.
func (d *EchoDiscoverer) extractHandlerName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if ident, ok := e.X.(*ast.Ident); ok {
			return ident.Name + "." + e.Sel.Name
		}
	case *ast.CallExpr:
		return astutil.GetCallName(e)
	}
	return ""
}
