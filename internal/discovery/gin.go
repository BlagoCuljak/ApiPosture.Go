package discovery

import (
	"go/ast"
	"strings"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/authorization"
	"github.com/BlagoCuljak/ApiPosture.Go/internal/models"
)

const ginImport = "github.com/gin-gonic/gin"

// ginRouteMethods maps Gin method names to HTTP methods.
var ginRouteMethods = map[string]models.HTTPMethod{
	"GET":     models.MethodGET,
	"POST":    models.MethodPOST,
	"PUT":     models.MethodPUT,
	"DELETE":  models.MethodDELETE,
	"PATCH":   models.MethodPATCH,
	"HEAD":    models.MethodHEAD,
	"OPTIONS": models.MethodOPTIONS,
}

// GinDiscoverer discovers endpoints in Gin applications.
type GinDiscoverer struct {
	authExtractor *authorization.GinExtractor
}

// NewGinDiscoverer creates a new GinDiscoverer.
func NewGinDiscoverer() *GinDiscoverer {
	return &GinDiscoverer{
		authExtractor: authorization.NewGinExtractor(),
	}
}

// Framework returns the framework this discoverer handles.
func (d *GinDiscoverer) Framework() models.Framework {
	return models.FrameworkGin
}

// CanHandle returns true if the source imports Gin.
func (d *GinDiscoverer) CanHandle(source *astutil.ParsedSource) bool {
	return source.HasImport(ginImport)
}

// Discover finds all Gin endpoints in the source.
func (d *GinDiscoverer) Discover(source *astutil.ParsedSource) ([]*models.Endpoint, error) {
	var endpoints []*models.Endpoint

	// Find router variables and their group prefixes
	groups := d.findGroups(source)

	// Collect Use() middleware per variable so that router.Use(auth) propagates to routes
	useMiddleware := d.findUseMiddleware(source)

	// Find all route registrations
	ast.Inspect(source.AST, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}

		endpoint := d.extractEndpoint(call, source, groups, useMiddleware)
		if endpoint != nil {
			endpoints = append(endpoints, endpoint)
		}

		return true
	})

	return endpoints, nil
}

// findUseMiddleware collects all .Use() calls and groups them by receiver variable.
func (d *GinDiscoverer) findUseMiddleware(source *astutil.ParsedSource) map[string][]string {
	useMiddleware := make(map[string][]string)

	ast.Inspect(source.AST, func(n ast.Node) bool {
		stmt, ok := n.(*ast.ExprStmt)
		if !ok {
			return true
		}
		call, ok := stmt.X.(*ast.CallExpr)
		if !ok {
			return true
		}
		callName := astutil.GetCallName(call)
		if !strings.HasSuffix(callName, ".Use") {
			return true
		}
		parts := strings.SplitN(callName, ".", 2)
		if len(parts) < 2 {
			return true
		}
		receiverVar := parts[0]
		for _, arg := range call.Args {
			if fn := d.extractHandlerName(arg); fn != "" {
				useMiddleware[receiverVar] = append(useMiddleware[receiverVar], fn)
			}
		}
		return true
	})

	return useMiddleware
}

// GroupInfo stores information about a Gin router group.
type GroupInfo struct {
	Prefix     string
	Middleware []string
	VarName    string
	ParentVar  string
}

// findGroups finds all Gin Group() calls and their prefixes/middleware.
func (d *GinDiscoverer) findGroups(source *astutil.ParsedSource) map[string]*GroupInfo {
	groups := make(map[string]*GroupInfo)

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

		group := &GroupInfo{
			VarName: ident.Name,
		}

		// Capture the receiver variable (e.g. for `v1 := r.Group(...)`, parentVar = "r")
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
			if parentIdent, ok2 := sel.X.(*ast.Ident); ok2 {
				group.ParentVar = parentIdent.Name
			}
		}

		// Extract prefix
		if len(call.Args) > 0 {
			group.Prefix = astutil.GetStringValue(call.Args[0])
		}

		// Extract middleware (handlers after the path)
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
func (d *GinDiscoverer) extractEndpoint(call *ast.CallExpr, source *astutil.ParsedSource, groups map[string]*GroupInfo, useMiddleware map[string][]string) *models.Endpoint {
	callName := astutil.GetCallName(call)
	parts := strings.Split(callName, ".")

	if len(parts) < 2 {
		return nil
	}

	receiverVar := parts[0]
	methodName := parts[1]

	// Check if this is a route method
	httpMethod, isRoute := ginRouteMethods[methodName]
	if !isRoute {
		// Check for Handle() which takes method as first argument
		if methodName == "Handle" && len(call.Args) >= 2 {
			methodStr := astutil.GetStringValue(call.Args[0])
			httpMethod, isRoute = ginRouteMethods[methodStr]
			if !isRoute {
				return nil
			}
			// Shift args for Handle case
			call.Args = call.Args[1:]
		} else if methodName == "Any" {
			// Any() matches all methods
			return d.createEndpoint(call, source, groups, useMiddleware, receiverVar,
				[]models.HTTPMethod{models.MethodGET, models.MethodPOST, models.MethodPUT,
					models.MethodDELETE, models.MethodPATCH, models.MethodHEAD, models.MethodOPTIONS})
		} else {
			return nil
		}
	}

	return d.createEndpoint(call, source, groups, useMiddleware, receiverVar, []models.HTTPMethod{httpMethod})
}

// createEndpoint creates an Endpoint from a route call.
func (d *GinDiscoverer) createEndpoint(call *ast.CallExpr, source *astutil.ParsedSource, groups map[string]*GroupInfo, useMiddleware map[string][]string, receiverVar string, methods []models.HTTPMethod) *models.Endpoint {
	if len(call.Args) < 1 {
		return nil
	}

	route := astutil.GetStringValue(call.Args[0])
	if route == "" {
		return nil
	}

	// Extract handler name (last argument)
	handlerName := ""
	if len(call.Args) >= 2 {
		handlerName = d.extractHandlerName(call.Args[len(call.Args)-1])
	}

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

		// Prepend Use() middleware from parent group, then from this group
		if group.ParentVar != "" {
			if parentUseMW, ok2 := useMiddleware[group.ParentVar]; ok2 {
				groupMiddleware = append(parentUseMW, groupMiddleware...)
			}
		}
	}

	// Prepend Use() middleware called on the receiver variable itself
	var useMW []string
	if mw, ok := useMiddleware[receiverVar]; ok {
		useMW = mw
	}

	// Extract authorization info: Use()-based MW comes first, then group MW, then inline MW
	allMiddleware := append(useMW, append(groupMiddleware, middleware...)...)
	auth := d.authExtractor.Extract(allMiddleware, source)

	endpoint := &models.Endpoint{
		Route:         route,
		Methods:       methods,
		FilePath:      source.FilePath,
		LineNumber:    astutil.GetLineNumber(source.FileSet, call),
		Framework:     models.FrameworkGin,
		EndpointType:  models.EndpointTypeFunction,
		FunctionName:  handlerName,
		Authorization: auth,
		RouterPrefix:  prefix,
	}

	return endpoint
}

// extractHandlerName extracts the function name from a handler argument.
func (d *GinDiscoverer) extractHandlerName(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		if ident, ok := e.X.(*ast.Ident); ok {
			return ident.Name + "." + e.Sel.Name
		}
	case *ast.CallExpr:
		// Handler might be returned from a function call (e.g., middleware factory)
		return astutil.GetCallName(e)
	}
	return ""
}
