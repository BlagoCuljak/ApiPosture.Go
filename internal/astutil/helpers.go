package astutil

import (
	"go/ast"
	"go/token"
	"strconv"
	"strings"
)

// GetCallName returns the name of a function call (e.g., "r.GET" or "http.HandleFunc").
func GetCallName(call *ast.CallExpr) string {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name
	case *ast.SelectorExpr:
		if x, ok := fun.X.(*ast.Ident); ok {
			return x.Name + "." + fun.Sel.Name
		}
		// Handle chained selectors like a.b.c
		return selectorToString(fun)
	}
	return ""
}

// selectorToString converts a SelectorExpr to a dotted string.
func selectorToString(sel *ast.SelectorExpr) string {
	var parts []string
	for {
		parts = append([]string{sel.Sel.Name}, parts...)
		switch x := sel.X.(type) {
		case *ast.Ident:
			parts = append([]string{x.Name}, parts...)
			return strings.Join(parts, ".")
		case *ast.SelectorExpr:
			sel = x
		default:
			return strings.Join(parts, ".")
		}
	}
}

// GetStringValue extracts the string value from an expression.
func GetStringValue(expr ast.Expr) string {
	switch e := expr.(type) {
	case *ast.BasicLit:
		if e.Kind.String() == "STRING" {
			// Remove quotes
			s, err := strconv.Unquote(e.Value)
			if err == nil {
				return s
			}
			return strings.Trim(e.Value, `"'`)
		}
	case *ast.Ident:
		// Variable reference - can't resolve at compile time
		return ""
	}
	return ""
}

// GetStringSlice extracts a []string from an array/slice literal.
func GetStringSlice(expr ast.Expr) []string {
	var result []string

	switch e := expr.(type) {
	case *ast.CompositeLit:
		for _, elt := range e.Elts {
			if s := GetStringValue(elt); s != "" {
				result = append(result, s)
			}
		}
	}

	return result
}

// FindFuncDecls returns all function declarations in a file.
func FindFuncDecls(file *ast.File) []*ast.FuncDecl {
	var funcs []*ast.FuncDecl
	for _, decl := range file.Decls {
		if fn, ok := decl.(*ast.FuncDecl); ok {
			funcs = append(funcs, fn)
		}
	}
	return funcs
}

// FindCallExprs returns all call expressions in a node.
func FindCallExprs(node ast.Node) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			calls = append(calls, call)
		}
		return true
	})
	return calls
}

// FindAssignments returns all assignment statements in a node.
func FindAssignments(node ast.Node) []*ast.AssignStmt {
	var assigns []*ast.AssignStmt
	ast.Inspect(node, func(n ast.Node) bool {
		if assign, ok := n.(*ast.AssignStmt); ok {
			assigns = append(assigns, assign)
		}
		return true
	})
	return assigns
}

// FindVarDecls returns all variable declarations in a node.
func FindVarDecls(node ast.Node) []*ast.GenDecl {
	var decls []*ast.GenDecl
	ast.Inspect(node, func(n ast.Node) bool {
		if gen, ok := n.(*ast.GenDecl); ok {
			decls = append(decls, gen)
		}
		return true
	})
	return decls
}

// GetReceiverName returns the receiver variable name for a method.
func GetReceiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	recv := fn.Recv.List[0]
	if len(recv.Names) == 0 {
		return ""
	}
	return recv.Names[0].Name
}

// GetReceiverType returns the receiver type name for a method.
func GetReceiverType(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	recv := fn.Recv.List[0]
	return typeToString(recv.Type)
}

// typeToString converts a type expression to a string.
func typeToString(expr ast.Expr) string {
	switch t := expr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		return "*" + typeToString(t.X)
	case *ast.SelectorExpr:
		return selectorToString(t)
	}
	return ""
}

// GetCallArg gets a specific argument from a function call (0-indexed).
func GetCallArg(call *ast.CallExpr, index int) ast.Expr {
	if index < 0 || index >= len(call.Args) {
		return nil
	}
	return call.Args[index]
}

// IsMethodCall checks if a call expression is a method call on a specific receiver.
func IsMethodCall(call *ast.CallExpr, receiverName, methodName string) bool {
	sel, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	if sel.Sel.Name != methodName {
		return false
	}

	if ident, ok := sel.X.(*ast.Ident); ok {
		return ident.Name == receiverName
	}

	return false
}

// FindMethodCalls finds all method calls matching a pattern in a node.
func FindMethodCalls(node ast.Node, methodName string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(node, func(n ast.Node) bool {
		if call, ok := n.(*ast.CallExpr); ok {
			if sel, ok := call.Fun.(*ast.SelectorExpr); ok {
				if sel.Sel.Name == methodName {
					calls = append(calls, call)
				}
			}
		}
		return true
	})
	return calls
}

// GetLineNumber returns the line number for an AST node.
func GetLineNumber(fset *token.FileSet, node ast.Node) int {
	return fset.Position(node.Pos()).Line
}
