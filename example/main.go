package main

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"flag"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/addrummond/datastargostrictcsp"

	"github.com/air-verse/air/runner"
	"github.com/starfederation/datastar-go/datastar"
)

var airReloadScriptHash = func() string {
	h := sha256.Sum256([]byte(runner.ProxyScript))
	return base64.StdEncoding.EncodeToString(h[:])
}()

// ── data model ────────────────────────────────────────────────────────────────

type Todo struct {
	ID        int
	Text      string
	Completed bool
}

var (
	mu    sync.Mutex
	todos = []Todo{
		{ID: 1, Text: "Learn Datastar", Completed: false},
		{ID: 2, Text: "Build something cool", Completed: false},
	}
	nextID = 3
)

// ── templates ─────────────────────────────────────────────────────────────────

type templateData struct {
	Todos []Todo
	Nonce string
	Lite  bool
}

type clockData struct {
	Time string
	Date string
}

const clockHTML = `{{define "clock"}}<div id="clock-display"><span class="clock-time">{{.Time}}</span><span class="clock-date">{{.Date}}</span></div>{{end}}`

//go:embed templates
var templateFS embed.FS

var tmpl = func() *template.Template {
	t := template.Must(template.New("root").Parse(clockHTML))
	for _, name := range []string{
		"templates/page.html",
		"templates/todo_list.html",
		"templates/todo_list_plain.html",
	} {
		content, err := templateFS.ReadFile(name)
		if err != nil {
			panic(err)
		}
		template.Must(t.Parse(string(content)))
	}
	return t
}()

// ── middleware ─────────────────────────────────────────────────────────────────

var csp = "default-src 'self'; " +
	"script-src 'self' https://cdn.jsdelivr.net/gh/starfederation/datastar@1.0.0-RC.8/bundles/datastar.js " +
	"'sha256-" + airReloadScriptHash + "'; " +
	"style-src 'self' 'unsafe-inline'; " +
	"connect-src 'self' https://cdn.jsdelivr.net/gh/starfederation/datastar@1.0.0-RC.8/bundles/datastar.js.map;"

func cspMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", csp)
		next.ServeHTTP(w, r)
	})
}

// ── handlers ──────────────────────────────────────────────────────────────────

func handleIndex(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	ts := make([]Todo, len(todos))
	copy(ts, todos)
	mu.Unlock()

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := templateData{Todos: ts, Nonce: datastargostrictcsp.NonceFromContext(r.Context()), Lite: r.URL.Query().Get("lite") != "false"}
	if err := tmpl.ExecuteTemplate(w, "page", data); err != nil {
		log.Println("template:", err)
	}
}

// ── counter ───────────────────────────────────────────────────────────────────

type counterSignals struct {
	Count int `json:"count"`
}

func handleCounterIncrement(w http.ResponseWriter, r *http.Request) {
	var sig counterSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sig.Count++
	sse := datastar.NewSSE(w, r)
	if err := sse.MarshalAndPatchSignals(sig); err != nil {
		log.Println("sse:", err)
	}
}

func handleCounterDecrement(w http.ResponseWriter, r *http.Request) {
	var sig counterSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sig.Count--
	sse := datastar.NewSSE(w, r)
	if err := sse.MarshalAndPatchSignals(sig); err != nil {
		log.Println("sse:", err)
	}
}

func handleCounterReset(w http.ResponseWriter, r *http.Request) {
	sse := datastar.NewSSE(w, r)
	if err := sse.MarshalAndPatchSignals(counterSignals{Count: 0}); err != nil {
		log.Println("sse:", err)
	}
}

// ── todos ─────────────────────────────────────────────────────────────────────

type todoSignals struct {
	NewTodo string `json:"newTodo"`
}

func renderTodoList(nonce string) (string, error) {
	mu.Lock()
	ts := make([]Todo, len(todos))
	copy(ts, todos)
	mu.Unlock()

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "todoList", templateData{Todos: ts, Nonce: nonce}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func renderTodoListPlain(nonce string) (string, error) {
	mu.Lock()
	ts := make([]Todo, len(todos))
	copy(ts, todos)
	mu.Unlock()

	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "todoListPlain", templateData{Todos: ts, Nonce: nonce}); err != nil {
		return "", err
	}
	return buf.String(), nil
}

func writePlainFragment(w http.ResponseWriter, nonce string) {
	html, err := renderTodoListPlain(nonce)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, html)
}

func handleTodosPlainGet(w http.ResponseWriter, r *http.Request) {
	writePlainFragment(w, datastargostrictcsp.NonceFromContext(r.Context()))
}

func handleTodosPlainAdd(w http.ResponseWriter, r *http.Request) {
	var sig struct {
		NewTodo2 string `json:"newTodo2"`
	}
	if err := datastar.ReadSignals(r, &sig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	text := strings.TrimSpace(sig.NewTodo2)
	if text == "" {
		http.Error(w, "empty todo", http.StatusBadRequest)
		return
	}
	mu.Lock()
	todos = append(todos, Todo{ID: nextID, Text: text})
	nextID++
	mu.Unlock()
	writePlainFragment(w, datastargostrictcsp.NonceFromContext(r.Context()))
}

func handleTodosPlainToggle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	mu.Lock()
	for i := range todos {
		if todos[i].ID == id {
			todos[i].Completed = !todos[i].Completed
			break
		}
	}
	mu.Unlock()
	writePlainFragment(w, datastargostrictcsp.NonceFromContext(r.Context()))
}

func handleTodosPlainDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}
	mu.Lock()
	for i, t := range todos {
		if t.ID == id {
			todos = append(todos[:i], todos[i+1:]...)
			break
		}
	}
	mu.Unlock()
	writePlainFragment(w, datastargostrictcsp.NonceFromContext(r.Context()))
}

func handleTodosAdd(w http.ResponseWriter, r *http.Request) {
	var sig todoSignals
	if err := datastar.ReadSignals(r, &sig); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	text := strings.TrimSpace(sig.NewTodo)
	if text == "" {
		http.Error(w, "empty todo", http.StatusBadRequest)
		return
	}

	mu.Lock()
	todos = append(todos, Todo{ID: nextID, Text: text})
	nextID++
	mu.Unlock()

	html, err := renderTodoList(datastargostrictcsp.NonceFromContext(r.Context()))
	if err != nil {
		log.Println("template:", err)
		return
	}

	sse := datastar.NewSSE(w, r)
	if err := sse.MarshalAndPatchSignals(todoSignals{NewTodo: ""}); err != nil {
		log.Println("sse:", err)
		return
	}
	if err := sse.PatchElements(html); err != nil {
		log.Println("sse:", err)
	}
}

func handleTodosToggle(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	mu.Lock()
	for i := range todos {
		if todos[i].ID == id {
			todos[i].Completed = !todos[i].Completed
			break
		}
	}
	mu.Unlock()

	html, err := renderTodoList(datastargostrictcsp.NonceFromContext(r.Context()))
	if err != nil {
		log.Println("template:", err)
		return
	}
	sse := datastar.NewSSE(w, r)
	if err := sse.PatchElements(html); err != nil {
		log.Println("sse:", err)
	}
}

func handleTodosDelete(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.Atoi(r.PathValue("id"))
	if err != nil {
		http.Error(w, "invalid id", http.StatusBadRequest)
		return
	}

	mu.Lock()
	for i, t := range todos {
		if t.ID == id {
			todos = append(todos[:i], todos[i+1:]...)
			break
		}
	}
	mu.Unlock()

	html, err := renderTodoList(datastargostrictcsp.NonceFromContext(r.Context()))
	if err != nil {
		log.Println("template:", err)
		return
	}
	sse := datastar.NewSSE(w, r)
	if err := sse.PatchElements(html); err != nil {
		log.Println("sse:", err)
	}
}

// ── clock ─────────────────────────────────────────────────────────────────────

func handleClock(w http.ResponseWriter, r *http.Request) {
	sse := datastar.NewSSE(w, r)
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	// Send an initial update immediately instead of waiting a full second.
	if err := patchClock(sse, time.Now()); err != nil {
		return
	}
	for {
		select {
		case <-r.Context().Done():
			return
		case t := <-ticker.C:
			if err := patchClock(sse, t); err != nil {
				return
			}
		}
	}
}

func patchClock(sse *datastar.ServerSentEventGenerator, t time.Time) error {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, "clock", clockData{
		Time: t.Format("15:04:05"),
		Date: t.Format("Monday, January 2, 2006"),
	}); err != nil {
		return err
	}
	return sse.PatchElements(buf.String())
}

// ── main ──────────────────────────────────────────────────────────────────────

var pc = func() *datastargostrictcsp.Precompiler {
	p := &datastargostrictcsp.Precompiler{}
	if _, err := rand.Read(p.Key[:]); err != nil {
		panic(err)
	}
	return p
}()

func main() {
	cert := flag.String("cert", "", "TLS certificate file (enables HTTPS)")
	key := flag.String("key", "", "TLS key file (enables HTTPS)")
	flag.Parse()

	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.Handle("GET /ds-precompile.js", pc.ScriptHandler())
	mux.HandleFunc("GET /{$}", handleIndex)
	mux.HandleFunc("GET /api/todos-plain", handleTodosPlainGet)
	mux.HandleFunc("POST /api/todos-plain", handleTodosPlainAdd)
	mux.HandleFunc("PUT /api/todos-plain/{id}", handleTodosPlainToggle)
	mux.HandleFunc("DELETE /api/todos-plain/{id}", handleTodosPlainDelete)
	mux.HandleFunc("POST /api/counter/increment", handleCounterIncrement)
	mux.HandleFunc("POST /api/counter/decrement", handleCounterDecrement)
	mux.HandleFunc("POST /api/counter/reset", handleCounterReset)
	mux.HandleFunc("POST /api/todos", handleTodosAdd)
	mux.HandleFunc("PUT /api/todos/{id}", handleTodosToggle)
	mux.HandleFunc("DELETE /api/todos/{id}", handleTodosDelete)
	mux.HandleFunc("GET /api/clock", handleClock)

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           cspMiddleware(datastargostrictcsp.NonceMiddleware(pc.Middleware(mux))),
		ReadTimeout:       15 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	if *cert != "" && *key != "" {
		fmt.Println("Listening on https://localhost:8080")
		if err := srv.ListenAndServeTLS(*cert, *key); err != nil {
			log.Fatal(err)
		}
	} else {
		fmt.Println("Listening on http://localhost:8080")
		if err := srv.ListenAndServe(); err != nil {
			log.Fatal(err)
		}
	}
}
