package discovery

import (
	"go/ast"
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/authorization"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

const fiberImport = "github.com/gofiber/fiber/v2"

// fiberRouteMethods maps Fiber method names to HTTP methods.
var fiberRouteMethods = map[string]models.HTTPMethod{
	"Get":     models.MethodGET,
	"Post":    models.MethodPOST,
	"Put":     models.MethodPUT,
	"Delete":  models.MethodDELETE,
	"Patch":   models.MethodPATCH,
	"Head":    models.MethodHEAD,
	"Options": models.MethodOPTIONS,
}

// FiberDiscoverer discovers endpoints in Fiber applications.
type FiberDiscoverer struct {
	authExtractor *authorization.FiberExtractor
}

// NewFiberDiscoverer creates a new FiberDiscoverer.
func NewFiberDiscoverer() *FiberDiscoverer {
	return &FiberDiscoverer{
		authExtractor: authorization.NewFiberExtractor(),
	}
}

// Framework returns the framework this discoverer handles.
func (d *FiberDiscoverer) Framework() models.Framework {
	return models.FrameworkFiber
}

// CanHandle returns true if the source imports Fiber.
func (d *FiberDiscoverer) CanHandle(source *astutil.ParsedSource) bool {
	return source.HasImport(fiberImport) || source.HasImportPrefix("github.com/gofiber/fiber")
}

// Discover finds all Fiber endpoints in the source.
func (d *FiberDiscoverer) Discover(source *astutil.ParsedSource) ([]*models.Endpoint, error) {
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

// FiberGroupInfo stores information about a Fiber router group.
type FiberGroupInfo struct {
	Prefix     string
	Middleware []string
	VarName    string
}

// findGroups finds all Fiber Group() calls.
func (d *FiberDiscoverer) findGroups(source *astutil.ParsedSource) map[string]*FiberGroupInfo {
	groups := make(map[string]*FiberGroupInfo)

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

		group := &FiberGroupInfo{
			VarName: ident.Name,
		}

		// Extract prefix
		if len(call.Args) > 0 {
			group.Prefix = astutil.GetStringValue(call.Args[0])
		}

		// Extract middleware (rest of arguments)
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
func (d *FiberDiscoverer) extractEndpoint(call *ast.CallExpr, source *astutil.ParsedSource, groups map[string]*FiberGroupInfo) *models.Endpoint {
	callName := astutil.GetCallName(call)
	parts := strings.Split(callName, ".")

	if len(parts) < 2 {
		return nil
	}

	receiverVar := parts[0]
	methodName := parts[1]

	// Check if this is a route method
	httpMethod, isRoute := fiberRouteMethods[methodName]
	if !isRoute {
		// Check for Add() which takes method as first argument
		if methodName == "Add" && len(call.Args) >= 3 {
			methodStr := astutil.GetStringValue(call.Args[0])
			if m, ok := map[string]models.HTTPMethod{
				"GET":     models.MethodGET,
				"POST":    models.MethodPOST,
				"PUT":     models.MethodPUT,
				"DELETE":  models.MethodDELETE,
				"PATCH":   models.MethodPATCH,
				"HEAD":    models.MethodHEAD,
				"OPTIONS": models.MethodOPTIONS,
			}[methodStr]; ok {
				httpMethod = m
				isRoute = true
			}
			if !isRoute {
				return nil
			}
			// Shift args for Add case
			call.Args = call.Args[1:]
		} else if methodName == "All" {
			// All() matches all methods
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
func (d *FiberDiscoverer) createEndpoint(call *ast.CallExpr, source *astutil.ParsedSource, groups map[string]*FiberGroupInfo, receiverVar string, methods []models.HTTPMethod) *models.Endpoint {
	if len(call.Args) < 2 {
		return nil
	}

	route := astutil.GetStringValue(call.Args[0])
	if route == "" {
		return nil
	}

	// Extract handler name (last argument)
	handlerName := d.extractHandlerName(call.Args[len(call.Args)-1])

	// Extract middleware (handlers between path and final handler)
	var middleware []string
	for i := 1; i < len(call.Args)-1; i++ {
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
		Framework:     models.FrameworkFiber,
		EndpointType:  models.EndpointTypeFunction,
		FunctionName:  handlerName,
		Authorization: auth,
		RouterPrefix:  prefix,
	}

	return endpoint
}

// extractHandlerName extracts the function name from a handler argument.
func (d *FiberDiscoverer) extractHandlerName(expr ast.Expr) string {
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
