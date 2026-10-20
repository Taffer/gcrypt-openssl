/* yat2m - extract man pages from a Texinfo source.
 *
 * Command-line compatible with the "Yet Another Texi To Man" converter
 * that ships with the reference libgpg-error and that GnuPG uses to
 * produce its man pages: same options, same Texinfo subset (the @manpage,
 * @mansect, @manpause and @mancont markers, @ifset manverb for verbatim
 * roff, "@c man:" lines, tables, examples and the usual inline commands),
 * same roff and HTML output, including the places where the reference
 * renders a construct oddly, so that a manual converted with either
 * program comes out identical.
 *
 * The converter works in two stages.  The reader goes through the input
 * line by line, expands macros, evaluates @ifset/@ifclear, follows
 * @include, and sorts the lines of each man page into named sections.
 * When a page is complete, the formatter renders every section in the
 * conventional order (NAME, SYNOPSIS, DESCRIPTION, ...), translating the
 * Texinfo markup into roff requests or HTML.
 *
 * This file is in the public domain.
 */

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define PGM "yat2m"
#define VERSION "1.1"

/* Marks a line stored in a section that must be copied to the output
 * verbatim (from "@ifset manverb").  It never occurs in Texinfo text. */
#define VERBATIM_MARK '\001'

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int any_error;

static void
die(const char *fmt, ...)
{
    va_list ap;

    fputs(PGM ": ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    putc('\n', stderr);
    exit(1);
}

static void
warn(const char *fmt, ...)
{
    va_list ap;

    fputs(PGM ": ", stderr);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    putc('\n', stderr);
}

/* A message about a specific input line.  These count as errors for the
 * exit status, as in the reference tool. */
static void
line_error(const char *file, int lineno, const char *fmt, ...)
{
    va_list ap;

    fprintf(stderr, "%s:%d: ", file, lineno);
    va_start(ap, fmt);
    vfprintf(stderr, fmt, ap);
    va_end(ap);
    putc('\n', stderr);
    any_error = 1;
}

static void *
xmalloc(size_t n)
{
    void *p = malloc(n ? n : 1);

    if (!p) {
        die("out of memory");
    }
    return p;
}

static void *
xrealloc(void *p, size_t n)
{
    void *q = realloc(p, n ? n : 1);

    if (!q) {
        die("out of memory");
    }
    return q;
}

static char *
xstrdup(const char *s)
{
    size_t n = strlen(s) + 1;
    char *p = xmalloc(n);

    memcpy(p, s, n);
    return p;
}

static char *
xstrndup(const char *s, size_t n)
{
    char *p = xmalloc(n + 1);

    memcpy(p, s, n);
    p[n] = 0;
    return p;
}

static int
is_space(int c)
{
    return c == ' ' || c == '\t';
}

static int
is_alnum(int c)
{
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z')
           || (c >= 'A' && c <= 'Z');
}

static int
to_upper(int c)
{
    return (c >= 'a' && c <= 'z') ? c - 'a' + 'A' : c;
}

static int
strcasecmp_ascii(const char *a, const char *b)
{
    while (*a && to_upper((unsigned char) * a) == to_upper((unsigned char) * b)) {
        a++;
        b++;
    }
    return to_upper((unsigned char) * a) - to_upper((unsigned char) * b);
}

/* A growable byte buffer. */
struct buf {
    char *data;
    size_t len;
    size_t cap;
};

static void
buf_reserve(struct buf *b, size_t extra)
{
    if (b->len + extra + 1 > b->cap) {
        size_t cap = b->cap ? b->cap : 256;

        while (cap < b->len + extra + 1) {
            cap *= 2;
        }
        b->data = xrealloc(b->data, cap);
        b->cap = cap;
    }
}

static void
buf_putc(struct buf *b, int c)
{
    buf_reserve(b, 1);
    b->data[b->len++] = (char)c;
    b->data[b->len] = 0;
}

static void
buf_append(struct buf *b, const char *s, size_t n)
{
    buf_reserve(b, n);
    memcpy(b->data + b->len, s, n);
    b->len += n;
    b->data[b->len] = 0;
}

static void
buf_puts(struct buf *b, const char *s)
{
    buf_append(b, s, strlen(s));
}

static void
buf_free(struct buf *b)
{
    free(b->data);
    b->data = NULL;
    b->len = b->cap = 0;
}

/* ------------------------------------------------------------------ */
/* Options and global tables                                           */
/* ------------------------------------------------------------------ */

static int opt_html;
static int opt_store;
static int opt_select_given;
static const char *opt_select;
static int opt_gnupgorg;
static int opt_verbose;
static int opt_debug;
static const char *opt_source = "GNU";
static const char *opt_release = "";
static time_t opt_date;
static int opt_date_given;

struct strlist {
    struct strlist *next;
    char *str;
};

static struct strlist *include_dirs;
static struct strlist *defines;

struct namevalue {
    struct namevalue *next;
    char *name;
    char *value;
};

/* Variables from @set, and macros without parameters from @macro. */
static struct namevalue *variables;
static struct namevalue *macros;

static void
strlist_append(struct strlist **list, const char *str)
{
    struct strlist *item = xmalloc(sizeof * item);
    struct strlist **pp = list;

    item->next = NULL;
    item->str = xstrdup(str);

    while (*pp) {
        pp = &(*pp)->next;
    }
    *pp = item;
}

static struct namevalue *
namevalue_find(struct namevalue *list, const char *name, size_t namelen)
{
    for (; list; list = list->next) {
        if (strlen(list->name) == namelen
            && !memcmp(list->name, name, namelen)) {
            return list;
        }
    }
    return NULL;
}

static void
namevalue_set(struct namevalue **list, const char *name, size_t namelen,
              const char *value)
{
    struct namevalue *nv = namevalue_find(*list, name, namelen);

    if (nv) {
        free(nv->value);
        nv->value = xstrdup(value);
        return;
    }
    nv = xmalloc(sizeof * nv);
    nv->name = xstrndup(name, namelen);
    nv->value = xstrdup(value);
    nv->next = *list;
    *list = nv;
}

/* Is NAME true for @ifset?  "isman" always is; so is anything given with
 * -D and any @set variable with a non-empty value. */
static int
condition_set(const char *name, size_t namelen)
{
    struct strlist *sl;
    struct namevalue *nv;

    if (namelen == 5 && !memcmp(name, "isman", 5)) {
        return 1;
    }
    for (sl = defines; sl; sl = sl->next) {
        if (strlen(sl->str) == namelen && !memcmp(sl->str, name, namelen)) {
            return 1;
        }
    }
    nv = namevalue_find(variables, name, namelen);
    return nv && *nv->value;
}

/* ------------------------------------------------------------------ */
/* Pages and sections                                                  */
/* ------------------------------------------------------------------ */

/* Sections whose position in the output is fixed, in output order.  Any
 * other section is placed right after the one created before it. */
static const char *const known_sections[] = {
    "NAME",        "SYNOPSIS",    "DESCRIPTION", "RETURN VALUE",
    "EXIT STATUS", "ERROR HANDLING", "ERRORS",   "COMMANDS",
    "OPTIONS",     "USAGE",       "EXAMPLES",    "FILES",
    "ENVIRONMENT", "DIAGNOSTICS", "SECURITY",    "CONFORMING TO",
    "ASSUAN",      "NOTES",       "BUGS",        "AUTHOR",
    "SEE ALSO"
};

#define N_KNOWN_SECTIONS (sizeof known_sections / sizeof known_sections[0])

struct section {
    struct section *next;
    char *name;  /* Upper case. */
    int rank;    /* Index into known_sections, or -1. */
    struct buf text;
};

struct page {
    char *name;    /* "gpg.1" */
    struct section *sections;
    struct section *current;
    struct section *last_created;
    int paused;
    int skip_heading; /* Drop the next line if it is a heading. */
};

static struct page *current_page;

static struct section *
find_section(struct page *pg, const char *name)
{
    struct section *s;

    for (s = pg->sections; s; s = s->next) {
        if (!strcasecmp_ascii(s->name, name)) {
            return s;
        }
    }
    return NULL;
}

static int
section_rank(const char *name)
{
    size_t i;

    for (i = 0; i < N_KNOWN_SECTIONS; i++) {
        if (!strcasecmp_ascii(known_sections[i], name)) {
            return (int)i;
        }
    }
    return -1;
}

/* Select section NAME of PG, creating it if needed.  A known section is
 * inserted before the first known section that follows it in the
 * conventional order; an unknown one goes after the most recently created
 * section, or is dropped when there is none yet. */
static void
select_section(struct page *pg, const char *name)
{
    struct section *s = find_section(pg, name);
    size_t i;

    if (s) {
        pg->current = s;
        return;
    }

    s = xmalloc(sizeof * s);
    s->next = NULL;
    s->name = xstrdup(name);

    for (i = 0; s->name[i]; i++) {
        s->name[i] = (char)to_upper((unsigned char)s->name[i]);
    }
    s->rank = section_rank(name);
    memset(&s->text, 0, sizeof s->text);

    if (s->rank >= 0) {
        struct section **pp = &pg->sections;

        while (*pp && !((*pp)->rank > s->rank)) {
            pp = &(*pp)->next;
        }
        s->next = *pp;
        *pp = s;
    } else if (pg->last_created) {
        s->next = pg->last_created->next;
        pg->last_created->next = s;
    } else {
        /* Nothing to attach it to: the reference tool loses it too. */
        free(s->name);
        free(s);
        pg->current = NULL;
        return;
    }
    pg->last_created = s;
    pg->current = s;
}

static void
free_page(struct page *pg)
{
    struct section *s, *next;

    for (s = pg->sections; s; s = next) {
        next = s->next;
        free(s->name);
        buf_free(&s->text);
        free(s);
    }
    free(pg->name);
    free(pg);
}

/* ------------------------------------------------------------------ */
/* Formatter                                                           */
/* ------------------------------------------------------------------ */

/* One open inline command, e.g. the "\fB" of @code waiting for its "}". */
struct inline_ctx {
    const char *close;  /* Emitted at the closing brace. */
    int escape;         /* Hyphens become "\-" inside (roff). */
};

#define MAX_INLINE 64
#define MAX_TABLES 32

struct fmt {
    FILE *out;
    const char *pending;  /* Replaces the next newline, if not NULL. */
    int pending_closes_li; /* HTML: emitting PENDING closes the <li>. */
    struct inline_ctx stack[MAX_INLINE];
    int depth;
    int in_example;
    int table_depth;
    int code_table[MAX_TABLES]; /* Per depth: items are code-like. */
    int item_line;   /* Text of an @item line of a code-like table. */
    size_t strip;    /* Leading blanks removed from each line (tables). */
    int at_line_start;
    int line_empty;  /* Nothing has been written for this line yet. */
    int see_also;    /* Formatting the SEE ALSO section. */
    int abort_section; /* Stop at once (a malformed command). */
    /* HTML only. */
    int list_depth;  /* @table and @itemize; only @end table closes. */
    int in_para;     /* A <p> has been opened in this section. */
};

static void format_run(struct fmt *f, const char *p, const char *end);

/* HTML: an <li> is open.  The reference tool keeps this across sections
 * and pages, and so does this one. */
static int html_li_open;

/* How hyphens are written at this point: 1 means every one becomes "\-"
 * (roff), 0 means "--" and "---" become dashes, and -1 leaves them
 * alone, which is what happens inside tables and inside markup such as
 * @var. */
static int
hyphen_mode(const struct fmt *f)
{
    if (f->in_example) {
        return opt_html ? -1 : 1;
    }
    if (f->depth) {
        return !opt_html && f->stack[f->depth - 1].escape ? 1 : -1;
    }
    if (f->item_line) {
        return opt_html ? -1 : 1;
    }
    if (opt_html ? f->list_depth : f->table_depth) {
        return -1;
    }
    return 0;
}

/* Emit the ordinary text S, applying the escaping of the current
 * context.  Used for input characters and for @value expansions. */
static void
emit_text(struct fmt *f, const char *s, size_t n)
{
    size_t i;

    for (i = 0; i < n; i++) {
        unsigned char c = (unsigned char)s[i];

        if (c == '-') {
            int mode = hyphen_mode(f);

            if (mode > 0) {
                fputs("\\-", f->out);
            } else if (mode < 0) {
                putc('-', f->out);
            } else if (i + 2 < n && s[i + 1] == '-' && s[i + 2] == '-') {
                fputs(opt_html ? "&mdash;" : "\\[em]", f->out);
                i += 2;
            } else if (i + 1 < n && s[i + 1] == '-') {
                fputs(opt_html ? "&ndash;" : "\\[en]", f->out);
                i += 1;
            } else {
                putc('-', f->out);
            }
        } else if (c == '\\') {
            fputs(opt_html ? "&bsol;" : "\\[rs]", f->out);
        } else if (opt_html && c == '<') {
            fputs("&lt;", f->out);
        } else if (opt_html && c == '>') {
            fputs("&gt;", f->out);
        } else if (opt_html && c == '&') {
            fputs("&amp;", f->out);
        } else {
            putc(c, f->out);
        }
    }
}

static void
push_inline(struct fmt *f, const char *open, const char *close, int escape)
{
    if (open) {
        fputs(open, f->out);
    }
    if (f->depth < MAX_INLINE) {
        f->stack[f->depth].close = close;
        f->stack[f->depth].escape = escape;
    }
    f->depth++;
}

static void
pop_inline(struct fmt *f)
{
    if (!f->depth) {
        return;
    }
    f->depth--;

    if (f->depth < MAX_INLINE && f->stack[f->depth].close) {
        fputs(f->stack[f->depth].close, f->out);
    }
}

/* Length of the command name starting at P (just after the '@').  The
 * escapes "@@", "@{" and "@}" are one character; any other name runs
 * until a blank, a brace or another '@'. */
static size_t
command_name_length(const char *p)
{
    size_t n = 0;

    if (*p == '@' || *p == '{' || *p == '}') {
        return 1;
    }
    while (p[n] && !is_space((unsigned char)p[n]) && p[n] != '\n'
           && p[n] != '{' && p[n] != '}' && p[n] != '@') {
        n++;
    }
    return n;
}

/* Skip P past a brace-delimited argument, honouring nesting; P points at
 * the opening brace.  Returns the position after the closing brace. */
static const char *
skip_braced(const char *p)
{
    int level = 0;

    for (; *p; p++) {
        if (*p == '{') {
            level++;
        } else if (*p == '}') {
            level--;

            if (level <= 0) {
                return p + 1;
            }
        }
    }
    return p;
}

static const char *
skip_to_eol(const char *p)
{
    while (*p && *p != '\n') {
        p++;
    }
    return p;
}

static void
set_pending(struct fmt *f, const char *text)
{
    f->pending = text;
    f->pending_closes_li = 0;
}

/* HTML: the start of a list or table. */
static void
html_open_list(struct fmt *f)
{
    if (html_li_open) {
        fputs("</li>\n", f->out);
        html_li_open = 0;
    }
    fputs("<ul>\n", f->out);
    f->list_depth++;
}

/* HTML: an @item or @itemx line.  The first word is copied as it is and
 * becomes the item, the rest is formatted as its arguments.  Returns the
 * position to continue from. */
static const char *
html_item(struct fmt *f, const char *rest, int is_itemx)
{
    const char *word;
    size_t wlen = 0;

    while (is_space((unsigned char) * rest)) {
        rest++;
    }
    if (!*rest || *rest == '\n') {
        set_pending(f, "");
        return rest;
    }
    word = rest;

    while (word[wlen] && !is_space((unsigned char)word[wlen])
           && word[wlen] != '\n') {
        wlen++;
    }
    rest = word + wlen;

    while (is_space((unsigned char) * rest)) {
        rest++;
    }

    if (is_itemx) {
        fputs("    <span class=\"y2m-item\">", f->out);
    } else {
        if (html_li_open) {
            fputs("</li>\n", f->out);
        }
        fputs("<li><span class=\"y2m-item\">", f->out);
        html_li_open = 1;
    }
    for (; wlen; wlen--, word++) {
        if (*word == '<') {
            fputs("&lt;", f->out);
        } else if (*word == '>') {
            fputs("&gt;", f->out);
        } else if (*word == '&') {
            fputs("&amp;", f->out);
        } else {
            putc(*word, f->out);
        }
    }
    if (*rest && *rest != '\n') {
        fputs(" <span class=\"y2m-args\">", f->out);
        set_pending(f, "</span></span>\n");
    } else {
        set_pending(f, "</span>\n");
    }
    return rest;
}

/* A @-command inside the text of a section.  P points at the character
 * after the '@'.  Returns the position to continue from. */
static const char *
format_command(struct fmt *f, const char *p)
{
    size_t n = command_name_length(p);
    const char *name = p;
    const char *rest = p + n;
    int braced = *rest == '{';
    FILE *out = f->out;

#define IS(s) (n == sizeof(s) - 1 && !memcmp(name, s, n))

    /* Single character commands. */
    if (IS("@") || IS("{") || IS("}")) {
        putc(*name, out);
        return rest;
    }
    if (IS("*")) {
        if (!opt_html) {
            fputs("\n.br", out);
        }
        return rest;
    }
    if (IS(":")) {
        return rest;
    }
    if (IS("!") || IS("?") || IS(".")) {
        putc(*name, out);
        return rest;
    }

    /* Comments; "@c man:" carries verbatim roff. */
    if (IS("c")) {
        if (!strncmp(rest, " man:", 5)) {
            const char *eol = skip_to_eol(rest + 5);

            if (!opt_html) {
                fwrite(rest + 5, 1, (size_t)(eol - rest - 5), out);
                putc('\n', out);
            } else {
                warn("unknown special comment \"man:\"");
            }
            set_pending(f, "");
            return eol;
        }
        set_pending(f, "");
        return skip_to_eol(rest);
    }

    /* Index entries and the headings the man page does not show. */
    if (IS("cindex") || IS("opindex") || IS("efindex") || IS("cpindex")
        || IS("section") || IS("chapter")) {
        set_pending(f, "");
        return skip_to_eol(rest);
    }

    if (IS("subsection")) {
        if (opt_html) {
            fputs("<h3>", out);
            set_pending(f, "</h3>\n");
        } else {
            fputs("\n.SS ", out);
            set_pending(f, "\n\\ \n");
        }
        return rest;
    }

    if (IS("chapheading") || IS("noindent")) {
        return rest;
    }

    /* Block structure.  @itemize nests like @table; only "@end table"
     * closes a level, as in the reference tool. */
    if (IS("table") || IS("itemize")) {
        const char *arg = rest;
        size_t alen;
        int code_like = 0;

        while (is_space((unsigned char) * arg)) {
            arg++;
        }
        alen = *arg == '@' ? command_name_length(arg + 1) : 0;
#define ARG_IS(s) (alen == sizeof(s) - 1 && !memcmp(arg + 1, s, alen))

        if (ARG_IS("code") || ARG_IS("command") || ARG_IS("option")
            || ARG_IS("samp") || ARG_IS("file") || ARG_IS("env")
            || ARG_IS("kbd") || ARG_IS("url") || ARG_IS("gnupgtabopt")) {
            code_like = 1;
        }
#undef ARG_IS
        f->table_depth++;

        if (f->table_depth < MAX_TABLES) {
            f->code_table[f->table_depth] = code_like;
        }
        if (opt_html) {
            html_open_list(f);
        } else if (f->table_depth > 1) {
            fputs(".RS\n", out);
        }
        set_pending(f, "");
        return skip_to_eol(rest);
    }

    if (IS("item") || IS("itemx")) {
        if (opt_html) {
            return html_item(f, rest, IS("itemx"));
        }
        fputs(IS("item") ? ".TP\n.B " : ".TQ\n.B ", out);
        f->item_line = f->table_depth && f->table_depth < MAX_TABLES
                       ? f->code_table[f->table_depth] : 0;
        return rest;
    }

    if (IS("example") || IS("smallexample")) {
        fputs(opt_html ? "\n<pre>\n" : ".RS 2\n.nf\n", out);
        f->in_example = 1;
        set_pending(f, "");
        return skip_to_eol(rest);
    }

    if (IS("quotation")) {
        if (!opt_html) {
            fputs(".RS\n\\fB", out);
        }
        set_pending(f, "");
        return skip_to_eol(rest);
    }

    if (IS("cartouche")) {
        set_pending(f, "");
        return skip_to_eol(rest);
    }

    if (IS("end")) {
        const char *arg = rest;
        size_t alen = 0;

        while (is_space((unsigned char) * arg)) {
            arg++;
        }
        while (is_alnum((unsigned char)arg[alen])) {
            alen++;
        }
        set_pending(f, "");

        if (alen == 5 && !memcmp(arg, "table", 5)) {
            if (opt_html) {
                set_pending(f, html_li_open ? "</li>\n</ul>\n" : "</ul>\n");
                f->pending_closes_li = html_li_open;

                if (f->list_depth) {
                    f->list_depth--;
                }
            } else if (f->table_depth > 1) {
                fputs(".RE\n", out);
            } else {
                set_pending(f, ".P\n");
            }
            if (f->table_depth) {
                f->table_depth--;
            }
        } else if ((alen == 7 && !memcmp(arg, "example", 7))
                   || (alen == 12 && !memcmp(arg, "smallexample", 12))) {
            f->in_example = 0;
            set_pending(f, opt_html ? "</pre>\n" : ".fi\n.RE\n");
        } else if (alen == 9 && !memcmp(arg, "quotation", 9)) {
            /* The reference tool leaves a stray "xx" in HTML here. */
            set_pending(f, opt_html ? "xx" : "\\fR\n.RE\n");
        }
        return skip_to_eol(rest);
    }

    /* In SEE ALSO, "@command{NAME}(N)" links to that page's HTML. */
    if (opt_html && f->see_also && braced && IS("command")) {
        const char *close = skip_braced(rest);

        if (close > rest + 1 && close[-1] == '}' && *close == '(') {
            const char *paren = close + 1;

            while (*paren && *paren != ')' && *paren != '\n') {
                paren++;
            }
            if (*paren == ')') {
                const char *nm = rest + 1;
                size_t nlen = (size_t)(close - rest - 2);
                int slen = (int)(paren - close - 1);
                struct buf nbuf;
                struct namevalue *m;
                size_t i;

                /* The name is taken literally, except that a lone macro
                 * is expanded. */
                memset(&nbuf, 0, sizeof nbuf);
                m = nlen > 1 && *nm == '@'
                    ? namevalue_find(macros, nm + 1, nlen - 1) : NULL;

                if (m) {
                    nlen = strlen(m->value);

                    if (nlen && m->value[nlen - 1] == '\n') {
                        nlen--;
                    }
                    nm = m->value;
                }
                for (i = 0; i < nlen; i++) {
                    if (nm[i] == '<') {
                        buf_puts(&nbuf, "&lt;");
                    } else if (nm[i] == '>') {
                        buf_puts(&nbuf, "&gt;");
                    } else if (nm[i] == '&') {
                        buf_puts(&nbuf, "&amp;");
                    } else {
                        buf_putc(&nbuf, nm[i]);
                    }
                }
                fprintf(out, "<i><a href=\"%s.%.*s.html\">%s</a>(%.*s)</i>",
                        nbuf.data ? nbuf.data : "", slen, close + 1,
                        nbuf.data ? nbuf.data : "", slen, close + 1);
                buf_free(&nbuf);
                return paren + 1;
            }
        }
    }

    /* A macro without parameters: its body is formatted in place. */
    {
        struct namevalue *m = namevalue_find(macros, name, n);

        if (m) {
            size_t blen = strlen(m->value);

            if (blen && m->value[blen - 1] == '\n') {
                blen--;
            }
            format_run(f, m->value, m->value + blen);

            if (rest[0] == '{' && rest[1] == '}') {
                return rest + 2;
            }
            return rest;
        }
    }

    /* Inline markup. */
    {
        static const struct {
            const char *name;
            const char *roff_open, *roff_close;
            int roff_escape;
            const char *html_open, *html_close;
        } markup[] = {
            { "code",     "\\fB", "\\fP", 1, "<samp>", "</samp>" },
            { "command",  "\\fB", "\\fP", 1, "<i>", "</i>" },
            { "option",   "\\fB", "\\fP", 1, "<samp>", "</samp>" },
            { "url",      "\\fB", "\\fP", 1, "<strong>", "</strong>" },
            {
                "sc",       "\\fB", "\\fP", 0, "<span class=\"y2m-sc\">",
                "</span>"
            },
            { "uref",     "(\\fB", "\\fP)", 0, "", "" },
            { "var",      "\\fI", "\\fP", 0, "<u>", "</u>" },
            { "emph",     "\\fI", "\\fP", 0, "<em>", "</em>" },
            { "file",     "\\(oq\\fI", "\\fP\\(cq", 1, "", "" },
            { "env",      "\\(oq\\fI", "\\fP\\(cq", 1, "", "" },
            { "samp",     "\\(oq", "\\(cq", 1, "", "" },
            { "kbd",      "\\(oq", "\\(cq", 1, "", "" },
            { "acronym",  "", "", 0, "", "" },
            { "dfn",      "", "", 0, "", "" },
            { "xref",     "See: [", "]", 0, "", "" },
            { "pxref",    "see: [", "]", 0, "", "" },
            { "ref",      "[", "]", 0, "", "" },
            { "footnote", " ([", "])", 0, "", "" },
        };
        size_t i;

        for (i = 0; i < sizeof markup / sizeof markup[0]; i++) {
            if (strlen(markup[i].name) == n
                && !memcmp(markup[i].name, name, n)) {
                const char *open = opt_html ? markup[i].html_open
                                   : markup[i].roff_open;
                const char *close = opt_html ? markup[i].html_close
                                    : markup[i].roff_close;

                if (!braced) {
                    /* No argument: the markup opens and closes at once. */
                    fputs(open, out);
                    fputs(close, out);
                    return rest;
                }
                push_inline(f, open, close, markup[i].roff_escape);
                return rest + 1;
            }
        }
    }

    /* Commands whose argument is dropped. */
    if (IS("anchor") || IS("asis")) {
        return braced ? skip_braced(rest) : rest;
    }

    /* @w drops its argument and then, as the reference tool does,
     * everything up to the next closing brace or the end of the line,
     * newline included. */
    if (IS("w")) {
        p = braced ? skip_braced(rest) : rest;

        while (*p && *p != '\n' && *p != '}') {
            p++;
        }
        return *p == '\n' ? p + 1 : p;
    }

    if (IS("dots")) {
        fputs(opt_html ? "&hellip;" : "...", out);
        return braced ? skip_braced(rest) : rest;
    }
    if (IS("minus")) {
        fputs(opt_html ? "&minus;" : "\\-", out);
        return braced ? skip_braced(rest) : rest;
    }
    if (IS("bullet")) {
        if (!opt_html) {
            fputs("* ", out);
        }
        return braced ? skip_braced(rest) : rest;
    }

    if (IS("value")) {
        if (braced) {
            const char *end = skip_braced(rest);
            size_t vlen = (size_t)(end - rest) >= 2 ? (size_t)(end - rest) - 2
                          : 0;
            struct namevalue *nv = namevalue_find(variables, rest + 1, vlen);

            if (nv) {
                emit_text(f, nv->value, strlen(nv->value));
            } else {
                warn("texinfo variable '%.*s' is not set", (int)vlen,
                     rest + 1);
            }
            return end;
        }
        /* The reference tool gives up on the section here. */
        warn("opening brace for command 'value' missing");
        any_error = 1;
        f->abort_section = 1;
        return rest;
    }

    /* Anything else is reported and its name dropped; the text that
     * follows, braces removed, stays. */
    {
        const char *eol = skip_to_eol(rest);

        warn("texinfo command '%.*s' not supported (%.*s)", (int)n, name,
             (int)(eol - rest), rest);
    }

    if (braced) {
        push_inline(f, NULL, "", 0);
        return rest + 1;
    }
    return rest;

#undef IS
}

/* HTML: render one verbatim roff line (without its newline) the way the
 * reference tool does: the common font requests become markup, other
 * requests and plain text pass through, and lines with escapes other
 * than a leading "\-" collapse to a line break. */
static void
html_verbatim_line(FILE *out, const char *line, size_t len, int newline)
{
    const char *nl = newline ? "\n" : "";
    static const struct {
        const char *req;
        const char *fonts;  /* Alternating fonts: R, I or B. */
    } alt[] = {
        { ".RI ", "RI" }, { ".IR ", "IR" }, { ".RB ", "RB" },
        { ".BR ", "BR" }, { ".IB ", "IB" }, { ".BI ", "BI" },
    };
    size_t i;

    if (len >= 3 && (!memcmp(line, ".B ", 3) || !memcmp(line, ".I ", 3))) {
        const char *tag = line[1] == 'B' ? "strong" : "em";

        fprintf(out, "<%s>", tag);

        for (i = 3; i < len; i++) {
            if (line[i] != '\\') {
                putc(line[i], out);
            }
        }
        fprintf(out, "</%s>%s", tag, nl);
        return;
    }

    for (i = 0; i < sizeof alt / sizeof alt[0]; i++) {
        if (len >= 4 && !memcmp(line, alt[i].req, 4)) {
            const char *p = line + 4;
            const char *end = line + len;
            int which = 0;
            int first = 1;

            while (p < end) {
                const char *word = p;
                const char *tag;

                while (p < end && *p != ' ') {
                    p++;
                }
                if (p == word) {
                    /* An extra blank between words: one more space. */
                    fputs(" ", out);
                } else {
                    char c = alt[i].fonts[which];

                    if (!first) {
                        fputs("  ", out);
                    }
                    first = 0;

                    tag = c == 'R' ? "span" : c == 'I' ? "em" : "strong";
                    fprintf(out, "<%s>", tag);

                    for (; word < p; word++) {
                        if (*word != '\\') {
                            putc(*word, out);
                        }
                    }
                    fprintf(out, "</%s>", tag);
                    which = !which;
                }
                if (p < end) {
                    p++;
                }
            }
            fputs(nl, out);
            return;
        }
    }

    if (len == 3 && !memcmp(line, ".br", 3)) {
        fprintf(out, "<br/>%s", nl);
        return;
    }

    if (len >= 2 && line[0] == '\\' && line[1] == '-') {
        fputs(" &mdash;", out);
        fwrite(line + 2, 1, len - 2, out);
        fputs(nl, out);
        return;
    }

    if (memchr(line, '\\', len)) {
        fprintf(out, "<br/>\n%s", nl);
        return;
    }

    fwrite(line, 1, len, out);
    fputs(nl, out);
}

/* A newline that ends an empty line, or ends the section while nothing
 * else is on the line. */
static void
emit_blank_line(struct fmt *f)
{
    if (!opt_html || f->list_depth || f->in_example) {
        putc('\n', f->out);
    } else if (f->in_para) {
        fputs("</p>\n\n<p>\n", f->out);
    } else {
        fputs("\n<p>\n", f->out);
        f->in_para = 1;
    }
}

/* Format the characters from P to END with the state in F. */
static void
format_run(struct fmt *f, const char *p, const char *end)
{
    FILE *out = f->out;

    while (p < end && !f->abort_section) {
        if (f->at_line_start) {
            size_t blanks = 0;

            f->at_line_start = 0;
            f->item_line = 0;
            f->line_empty = 1;

            if (*p == VERBATIM_MARK) {
                const char *eol = p + 1;

                while (eol < end && *eol != '\n') {
                    eol++;
                }
                if (opt_html) {
                    html_verbatim_line(out, p + 1, (size_t)(eol - p - 1),
                                       eol < end);
                } else {
                    fwrite(p + 1, 1, (size_t)(eol - p - 1), out);

                    if (eol < end) {
                        putc('\n', out);
                    }
                }
                f->line_empty = 0;

                if (eol < end) {
                    f->at_line_start = 1;
                    p = eol + 1;
                } else {
                    p = eol;
                }
                continue;
            }

            while (p + blanks < end && is_space((unsigned char)p[blanks])) {
                blanks++;
            }
            if (!strncmp(p + blanks, "@item", 5)) {
                f->strip = blanks;
                p += blanks;
            } else if (*p == '\n') {
                /* An empty line leaves the table indentation alone. */
            } else if (blanks >= f->strip) {
                p += f->strip;
            } else {
                f->strip = 0;
            }
        }

        if (*p == '\n') {
            if (f->pending) {
                fputs(f->pending, out);

                if (f->pending_closes_li) {
                    html_li_open = 0;
                }
                f->pending = NULL;
            } else if (f->line_empty) {
                emit_blank_line(f);
            } else {
                putc('\n', out);
            }
            f->at_line_start = 1;
            p++;
        } else if (*p == '@') {
            const char *next = format_command(f, p + 1);

            f->line_empty = 0;

            /* A command may have swallowed the newline. */
            if (next > p && next[-1] == '\n') {
                f->at_line_start = 1;
            }
            p = next;
        } else if (*p == '}' && f->depth) {
            pop_inline(f);
            f->line_empty = 0;
            p++;
        } else {
            size_t run = 0;

            while (p + run < end && p[run] != '\n' && p[run] != '@'
                   && (p[run] != '}' || !f->depth)) {
                run++;
            }
            emit_text(f, p, run);
            f->line_empty = 0;
            p += run;
        }
    }
}

/* Render the text of one section.  The final newline of the stored text
 * is not run through the pending mechanism: whatever a command at the
 * very end wanted to put in place of its newline is dropped and a plain
 * newline ends the section, exactly as the reference tool does. */
static void
format_section(FILE *out, const char *name, const char *text, size_t len)
{
    struct fmt f;

    memset(&f, 0, sizeof f);
    f.out = out;
    f.at_line_start = 1;
    f.line_empty = 1;
    f.see_also = !strcmp(name, "SEE ALSO");

    if (len && text[len - 1] == '\n') {
        len--;
    }

    if (opt_html) {
        if (len && *text == VERBATIM_MARK) {
            fputs("@para{}", out);
        } else {
            fputs("\n<p>", out);
            f.in_para = 1;
        }
    }

    format_run(&f, text, text + len);

    /* The final newline: a command's replacement for it is dropped, an
     * empty last line is a blank line, anything else just ends. */
    if (!f.pending && f.at_line_start) {
        emit_blank_line(&f);
    } else {
        putc('\n', out);
    }
}

/* The HTML header of a page. */
static void
html_prologue(FILE *out, const char *upper_name, const char *sect)
{
    if (opt_gnupgorg) {
        fputs("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n"
              "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\"\n"
              "         \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
              "<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" "
              "xml:lang=\"en\">\n",
              out);
    } else {
        fputs("<html>\n", out);
    }
    fprintf(out, "<head>\n <title>%s(%s)</title>\n", upper_name, sect);

    if (opt_gnupgorg) {
        fputs("<meta http-equiv=\"Content-Type\" "
              "content=\"text/html;charset=utf-8\" />\n"
              "<meta name=\"viewport\" "
              "content=\"width=device-width, initial-scale=1\" />\n"
              "<link rel=\"stylesheet\" href=\"/share/site.css\" "
              "type=\"text/css\" />\n",
              out);
    } else {
        fputs("<style type=\"text/css\">\n"
              "  .y2m {\n"
              "    font-family: monospace;\n"
              "  }\n"
              "  .y2m u {\n"
              "    text-decoration: underline;\n"
              "  }\n"
              "  .y2m-sc {\n"
              "    font-variant: small-caps;\n"
              "  }\n"
              "  .y2m li {\n"
              "    margin-top: 1em;\n"
              "  }\n"
              "  .y2m-item {\n"
              "     display: block;\n"
              "     font-weight: bold;\n"
              "  }\n"
              "  .y2m-args {\n"
              "     font-weight: normal;\n"
              "  }\n"
              "</style>\n",
              out);
    }
    fputs("</head>\n<body>\n", out);

    if (opt_gnupgorg) {
        fputs("<div id=\"wrapper\">\n<div id=\"content\">\n", out);
    }
    fputs("<div class=\"y2m\">\n", out);
    fprintf(out,
            "<p class=\"y2m y2m-top\"><span class=\"y2m-left\">%s(%s)</span> "
            "<span class=\"y2m-center\">%s</span> "
            "<span class=\"y2m-right\">%s(%s)</span></p>\n",
            upper_name, sect, opt_source, upper_name, sect);
}

static void
html_epilogue(FILE *out, const char *upper_name, const char *sect,
              const char *date)
{
    fprintf(out,
            "<p class=\"y2m y2m-footer\"><span class=\"y2m-left\">%s</span> "
            "<span class=\"y2m-center\">%s</span> "
            "<span class=\"y2m-right\">%s(%s)</span></p>\n",
            opt_release, date, upper_name, sect);
    fputs("</div><!-- class y2m -->\n", out);

    if (opt_gnupgorg) {
        fputs("</div><!-- end content -->\n</div><!-- end wrapper -->\n", out);
    }
    fputs("</body>\n</html>\n", out);
}

/* Write the finished page PG to OUT. */
static void
write_page(struct page *pg, FILE *out)
{
    const char *dot = strrchr(pg->name, '.');
    char *upper;
    const char *sect;
    char date[32];
    time_t t = opt_date_given ? opt_date : time(NULL);
    struct tm *tm = gmtime(&t);
    struct section *s;
    size_t i;

    if (opt_html) {
        fputs("<!-- Created from Texinfo source by yat2m " VERSION " -->\n",
              out);
    } else {
        fputs(".\\\" Created from Texinfo source by yat2m " VERSION "\n", out);
    }

    if (!dot || !dot[1]) {
        warn("no section name in man page '%s'", pg->name);
        any_error = 1;
        return;
    }
    sect = dot + 1;
    upper = xstrndup(pg->name, (size_t)(dot - pg->name));

    for (i = 0; upper[i]; i++) {
        upper[i] = (char)to_upper((unsigned char)upper[i]);
    }
    if (!tm || !strftime(date, sizeof date, "%Y-%m-%d", tm)) {
        strcpy(date, "1970-01-01");
    }

    if (opt_html) {
        html_prologue(out, upper, sect);
    } else {
        fprintf(out, ".TH %s %s %s \"%s\" \"%s\"\n", upper, sect, date,
                opt_release, opt_source);
    }

    for (s = pg->sections; s; s = s->next) {
        if (!s->text.len) {
            continue;
        }
        if (opt_html) {
            fprintf(out,
                    "<div class=\"y2m-section\">\n"
                    "<h2 class=\"y2m-sh\">%s</h2>\n",
                    s->name);
        } else {
            fprintf(out, ".SH %s\n", s->name);
        }
        format_section(out, s->name, s->text.data, s->text.len);

        if (opt_html) {
            fputs("</div>\n", out);
        }
    }

    if (opt_html) {
        html_epilogue(out, upper, sect, date);
    }
    free(upper);
}

/* The current page is complete: write it where it belongs. */
static void
finish_page(void)
{
    struct page *pg = current_page;

    if (!pg) {
        return;
    }
    current_page = NULL;

    if (opt_verbose) {
        warn("finishing page '%s'", pg->name);
    }

    if (opt_select_given) {
        if (!strcmp(opt_select, pg->name)) {
            warn("selected '%s'", pg->name);
            write_page(pg, stdout);
        }
    } else if (opt_store) {
        size_t n = strlen(pg->name);
        char *fname = xmalloc(n + 6);
        FILE *fp;

        memcpy(fname, pg->name, n + 1);

        if (opt_html) {
            strcpy(fname + n, ".html");
        }
        fp = fopen(fname, "w");

        if (!fp) {
            /* The reference tool follows this with an empty line. */
            die("failed to create '%s': %s\n", fname, strerror(errno));
        }
        write_page(pg, fp);

        if (ferror(fp) || fclose(fp)) {
            die("error writing '%s': %s", fname, strerror(errno));
        }
        free(fname);
    } else {
        write_page(pg, stdout);
    }
    free_page(pg);
}

static void
start_page(const char *name)
{
    struct page *pg;

    finish_page();
    pg = xmalloc(sizeof * pg);
    memset(pg, 0, sizeof * pg);
    pg->name = xstrdup(name);
    current_page = pg;

    if (opt_verbose) {
        warn("starting page '%s'", name);
    }
    /* Until the first @mansect, only verbatim roff reaches the page, and
     * it lands in NAME: that is how the pages state their name line. */
    select_section(pg, "name");
    pg->paused = 1;
}

/* ------------------------------------------------------------------ */
/* Reader                                                              */
/* ------------------------------------------------------------------ */

struct cond {
    int skip;      /* Lines are dropped while this is set. */
    int verbatim;  /* "@ifset manverb": lines are copied as roff. */
};

#define MAX_COND 64

static struct cond cond_stack[MAX_COND];
static int cond_depth;
static int finished;  /* "@bye" seen. */

/* Macro definition in progress. */
static int in_macro;
static int macro_has_params;
static char *macro_name;
static struct buf macro_body;

static int in_menu;

struct reader {
    const char *fname;
    int lineno;
};

static int
cond_skipping(void)
{
    int i;

    for (i = 0; i < cond_depth; i++) {
        if (cond_stack[i].skip) {
            return 1;
        }
    }
    return 0;
}

static int
cond_verbatim(void)
{
    return cond_depth && cond_stack[cond_depth - 1].verbatim;
}

/* Does LINE start with the @-command CMD, followed by a blank or the end
 * of the line?  Returns the position after the command name. */
static const char *
line_command(const char *line, const char *cmd)
{
    size_t n = strlen(cmd);

    if (*line != '@' || strncmp(line + 1, cmd, n)) {
        return NULL;
    }
    line += 1 + n;

    if (*line && !is_space((unsigned char) * line) && *line != '\n') {
        return NULL;
    }
    return line;
}

/* The rest of the line after a command: leading blanks and the newline
 * removed.  Returns a malloc'd copy. */
static char *
line_argument(const char *p)
{
    size_t n;

    while (is_space((unsigned char) * p)) {
        p++;
    }
    n = strlen(p);

    while (n && (p[n - 1] == '\n' || is_space((unsigned char)p[n - 1]))) {
        n--;
    }
    return xstrndup(p, n);
}

static void process_file(const char *fname, FILE *fp);

static FILE *
open_include(const char *name, char **used_name)
{
    FILE *fp = fopen(name, "r");
    struct strlist *sl;

    if (fp) {
        *used_name = xstrdup(name);
        return fp;
    }
    if (name[0] == '/') {
        return NULL;
    }
    for (sl = include_dirs; sl; sl = sl->next) {
        size_t n = strlen(sl->str) + strlen(name) + 2;
        char *path = xmalloc(n);

        sprintf(path, "%s/%s", sl->str, name);
        fp = fopen(path, "r");

        if (fp) {
            *used_name = path;
            return fp;
        }
        free(path);
    }
    return NULL;
}

/* Append LINE (with its newline) to the current section, if there is one
 * to take it. */
static void
store_line(const char *line, int verbatim)
{
    struct page *pg = current_page;

    if (!pg || !pg->current) {
        return;
    }
    if (!verbatim && pg->paused) {
        return;
    }
    if (verbatim) {
        buf_putc(&pg->current->text, VERBATIM_MARK);
    }
    buf_puts(&pg->current->text, line);
}

/* Handle one input line (ending in a newline) after macro expansion. */
static void
handle_line(struct reader *r, const char *line)
{
    const char *arg;

    if (finished) {
        return;
    }

    if (in_macro) {
        char *a = (arg = line_command(line, "end")) ? line_argument(arg) : NULL;

        if (a && !strcmp(a, "macro")) {
            /* The page markers are commands of their own, whatever the
             * source defines them as. */
            if (!macro_has_params && strcmp(macro_name, "manpage")
                && strcmp(macro_name, "mansect")
                && strcmp(macro_name, "manpause")
                && strcmp(macro_name, "mancont")) {
                namevalue_set(&macros, macro_name, strlen(macro_name),
                              macro_body.data ? macro_body.data : "");
            }
            in_macro = 0;
            free(macro_name);
            macro_name = NULL;
            buf_free(&macro_body);
        } else {
            buf_puts(&macro_body, line);
        }
        free(a);
        return;
    }

    if (in_menu) {
        if (line_command(line, "end")) {
            char *a = line_argument(line + 4);

            if (!strcmp(a, "menu")) {
                in_menu = 0;
            }
            free(a);
        }
        return;
    }

    /* Conditionals are tracked even inside skipped regions. */
    if ((arg = line_command(line, "ifset")) != NULL
        || (arg = line_command(line, "ifclear")) != NULL) {
        int is_ifset = line[3] == 's';
        char *name = line_argument(arg);
        struct cond c;

        c.skip = 0;
        c.verbatim = 0;

        if (cond_skipping()) {
            c.skip = 1;
        } else if (!strcmp(name, "manverb")) {
            if (!is_ifset) {
                line_error(r->fname, r->lineno,
                           "using \"@ifclear manverb\" is not allowed");
                free(name);
                return;
            }
            c.verbatim = 1;
        } else {
            int set = condition_set(name, strlen(name));

            c.skip = is_ifset ? !set : set;
        }
        if (cond_depth < MAX_COND) {
            cond_stack[cond_depth] = c;
        }
        cond_depth++;
        free(name);
        return;
    }

    if ((arg = line_command(line, "end")) != NULL) {
        char *a = line_argument(arg);

        if (!strcmp(a, "ifset") || !strcmp(a, "ifclear")) {
            if (!cond_depth) {
                line_error(r->fname, r->lineno, "unbalanced \"@end %s\"",
                           a[2] == 's' ? "isset" : "isclear");
            } else {
                cond_depth--;
            }
            free(a);
            return;
        }
        free(a);
    }

    if (cond_skipping()) {
        return;
    }

    if (cond_verbatim()) {
        store_line(line, 1);
        return;
    }

    if ((arg = line_command(line, "macro")) != NULL) {
        const char *p = arg;
        size_t n = 0;

        while (is_space((unsigned char) * p)) {
            p++;
        }
        while (p[n] && !is_space((unsigned char)p[n]) && p[n] != '{'
               && p[n] != '\n') {
            n++;
        }
        in_macro = 1;
        macro_name = xstrndup(p, n);
        p += n;

        while (is_space((unsigned char) * p)) {
            p++;
        }
        macro_has_params = *p == '{';
        memset(&macro_body, 0, sizeof macro_body);
        return;
    }

    if ((arg = line_command(line, "include")) != NULL) {
        char *name = line_argument(arg);
        char *used = NULL;
        FILE *fp = open_include(name, &used);

        if (!fp) {
            die("can't open include file '%s': %s", name, strerror(errno));
        }
        process_file(used, fp);
        fclose(fp);
        free(used);
        free(name);
        return;
    }

    if ((arg = line_command(line, "set")) != NULL) {
        const char *p = arg;
        size_t n = 0;
        char *value;

        while (is_space((unsigned char) * p)) {
            p++;
        }
        while (p[n] && !is_space((unsigned char)p[n]) && p[n] != '\n') {
            n++;
        }
        value = line_argument(p + n);
        namevalue_set(&variables, p, n, value);
        free(value);
        return;
    }

    if (line_command(line, "menu")) {
        in_menu = 1;
        return;
    }

    if (line_command(line, "node")) {
        return;
    }

    if (line_command(line, "bye")) {
        finished = 1;
        return;
    }

    if ((arg = line_command(line, "manpage")) != NULL) {
        char *name = line_argument(arg);

        start_page(name);
        free(name);
        return;
    }

    if ((arg = line_command(line, "mansect")) != NULL) {
        if (current_page) {
            char *name = line_argument(arg);

            select_section(current_page, name);
            current_page->paused = 0;
            current_page->skip_heading = 1;
            free(name);
        } else {
            line_error(r->fname, r->lineno, "section outside of a man page");
        }
        return;
    }

    if (line_command(line, "manpause")) {
        if (current_page) {
            current_page->paused = 1;
        }
        return;
    }

    if (line_command(line, "mancont")) {
        if (!current_page || !current_page->paused) {
            line_error(r->fname, r->lineno, "continue while not pausing");
        } else {
            current_page->paused = 0;
        }
        return;
    }

    if (current_page && current_page->skip_heading) {
        current_page->skip_heading = 0;

        if (line_command(line, "section") || line_command(line, "subsection")
            || line_command(line, "chapheading")) {
            return;
        }
    }

    store_line(line, 0);
}

/* Read FP line by line.  A final line without a newline is reported and
 * dropped, as the reference tool does. */
static void
process_file(const char *fname, FILE *fp)
{
    struct reader r;
    struct buf line;
    int c;

    r.fname = fname;
    r.lineno = 0;
    memset(&line, 0, sizeof line);

    for (;;) {
        line.len = 0;

        if (line.data) {
            line.data[0] = 0;
        }
        while ((c = getc(fp)) != EOF) {
            buf_putc(&line, c);

            if (c == '\n') {
                break;
            }
        }
        if (c == EOF && ferror(fp)) {
            line_error(fname, r.lineno, "read error: %s", strerror(errno));
            break;
        }
        if (!line.len) {
            break;
        }
        r.lineno++;

        if (line.data[line.len - 1] != '\n') {
            line_error(fname, r.lineno,
                       "trailing linefeed missing, line too long or "
                       "embedded Nul character");
            break;
        }
        handle_line(&r, line.data);

        if (finished) {
            break;
        }
    }
    buf_free(&line);
}

/* ------------------------------------------------------------------ */
/* Main                                                                */
/* ------------------------------------------------------------------ */

static void
usage(int status)
{
    if (status) {
        fputs(PGM ": usage: " PGM " [OPTION] [FILE] "
              "(try --help for more information)\n\n",
              stderr);
        exit(status);
    }
    fputs("Usage: " PGM " [OPTION] [FILE]\n"
          "Extract man pages from a Texinfo source.\n\n"
          "  --html           render output as HTML\n"
          "  --source NAME    use NAME as source field\n"
          "  --release STRING use STRING as the release field\n"
          "  --date EPOCH     use EPOCH as publication date\n"
          "  --store          write output using @manpage name\n"
          "  --select NAME    only output pages with @manpage NAME\n"
          "  --gnupgorg       prepare for use at www.gnupg.org\n"
          "  --verbose        enable extra informational output\n"
          "  --debug          enable additional debug output\n"
          "  --help           display this help and exit\n"
          "  -I DIR           also search in include DIR\n"
          "  -D MACRO         define MACRO to 1\n\n"
          "With no FILE, or when FILE is -, read standard input.\n\n"
          "This program is in the public domain.\n",
          stdout);
    exit(0);
}

int
main(int argc, char **argv)
{
    const char *fname = NULL;

    argc--;
    argv++;

    while (argc) {
        const char *a = *argv;

        if (!strcmp(a, "--")) {
            argc--;
            argv++;
            break;
        } else if (!strcmp(a, "--help") || !strcmp(a, "-h")) {
            usage(0);
        } else if (!strcmp(a, "--version")) {
            fputs(PGM " " VERSION "\n"
                  "gcrypt-openssl implementation; this program is in the "
                  "public domain.\n"
                  "There is NO WARRANTY, to the extent permitted by law.\n",
                  stdout);
            return 0;
        } else if (!strcmp(a, "--html")) {
            opt_html = 1;
        } else if (!strcmp(a, "--store")) {
            opt_store = 1;
        } else if (!strcmp(a, "--gnupgorg")) {
            opt_gnupgorg = 1;
        } else if (!strcmp(a, "--verbose")) {
            opt_verbose = 1;
        } else if (!strcmp(a, "--debug")) {
            opt_debug = 1;
            opt_verbose = 1;
        } else if (!strcmp(a, "--source") || !strcmp(a, "--release")
                   || !strcmp(a, "--date") || !strcmp(a, "--select")
                   || !strcmp(a, "-I") || !strcmp(a, "-D")) {
            if (argc < 2) {
                usage(1);
            }
            if (!strcmp(a, "--source")) {
                opt_source = argv[1];
            } else if (!strcmp(a, "--release")) {
                opt_release = argv[1];
            } else if (!strcmp(a, "--date")) {
                opt_date = (time_t)atol(argv[1]);
                opt_date_given = 1;
            } else if (!strcmp(a, "--select")) {
                opt_select = argv[1];
                opt_select_given = 1;
            } else if (!strcmp(a, "-I")) {
                strlist_append(&include_dirs, argv[1]);
            } else {
                strlist_append(&defines, argv[1]);
            }
            argc--;
            argv++;
        } else if (a[0] == '-' && a[1]) {
            usage(1);
        } else {
            break;
        }
        argc--;
        argv++;
    }

    if (argc > 1) {
        usage(1);
    }
    if (argc == 1 && strcmp(argv[0], "-")) {
        fname = argv[0];
    }

    (void)opt_debug;

    if (fname) {
        FILE *fp = fopen(fname, "r");

        if (!fp) {
            die("%s:0: can't open file: %s", fname, strerror(errno));
        }
        process_file(fname, fp);
        fclose(fp);
    } else {
        process_file("-", stdin);
    }
    finish_page();

    if (fflush(stdout) || ferror(stdout)) {
        die("error writing output: %s", strerror(errno));
    }
    return any_error ? 1 : 0;
}
