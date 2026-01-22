package analysis

import (
	"go/ast"
	"go/token"

	"github.com/BlagoCuljak/ApiPosture.Go/internal/astutil"
)

// Re-export helper functions from astutil for backward compatibility

// GetCallName returns the name of a function call (e.g., "r.GET" or "http.HandleFunc").
func GetCallName(call *ast.CallExpr) string {
	return astutil.GetCallName(call)
}

// GetStringValue extracts the string value from an expression.
func GetStringValue(expr ast.Expr) string {
	return astutil.GetStringValue(expr)
}

// GetStringSlice extracts a []string from an array/slice literal.
func GetStringSlice(expr ast.Expr) []string {
	return astutil.GetStringSlice(expr)
}

// FindFuncDecls returns all function declarations in a file.
func FindFuncDecls(file *ast.File) []*ast.FuncDecl {
	return astutil.FindFuncDecls(file)
}

// FindCallExprs returns all call expressions in a node.
func FindCallExprs(node ast.Node) []*ast.CallExpr {
	return astutil.FindCallExprs(node)
}

// FindAssignments returns all assignment statements in a node.
func FindAssignments(node ast.Node) []*ast.AssignStmt {
	return astutil.FindAssignments(node)
}

// FindVarDecls returns all variable declarations in a node.
func FindVarDecls(node ast.Node) []*ast.GenDecl {
	return astutil.FindVarDecls(node)
}

// GetReceiverName returns the receiver variable name for a method.
func GetReceiverName(fn *ast.FuncDecl) string {
	return astutil.GetReceiverName(fn)
}

// GetReceiverType returns the receiver type name for a method.
func GetReceiverType(fn *ast.FuncDecl) string {
	return astutil.GetReceiverType(fn)
}

// GetCallArg gets a specific argument from a function call (0-indexed).
func GetCallArg(call *ast.CallExpr, index int) ast.Expr {
	return astutil.GetCallArg(call, index)
}

// IsMethodCall checks if a call expression is a method call on a specific receiver.
func IsMethodCall(call *ast.CallExpr, receiverName, methodName string) bool {
	return astutil.IsMethodCall(call, receiverName, methodName)
}

// FindMethodCalls finds all method calls matching a pattern in a node.
func FindMethodCalls(node ast.Node, methodName string) []*ast.CallExpr {
	return astutil.FindMethodCalls(node, methodName)
}

// GetLineNumber returns the line number for an AST node.
func GetLineNumber(fset *token.FileSet, node ast.Node) int {
	return astutil.GetLineNumber(fset, node)
}
