// Package dsgin provides Gin middleware for datastargostrictcsp.
package dsgin

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// Adapt converts a standard net/http middleware (func(http.Handler) http.Handler)
// into a Gin handler function.
func Adapt(mw func(http.Handler) http.Handler) gin.HandlerFunc {
	return func(c *gin.Context) {
		mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			c.Request = r
			c.Next()
		})).ServeHTTP(c.Writer, c.Request)
	}
}
