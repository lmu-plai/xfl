--
-- PostgreSQL database dump
--

-- Dumped from database version 15.1 (Debian 15.1-1.pgdg110+1)
-- Dumped by pg_dump version 15.1 (Debian 15.1-1.pgdg110+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: architecture; Type: TYPE; Schema: public; Owner: desyl
--

CREATE TYPE public.architecture AS ENUM (
    'x86',
    'x86_64',
    'armv6',
    'armv7',
    'ppc64'
);


ALTER TYPE public.architecture OWNER TO desyl;

--
-- Name: binding; Type: TYPE; Schema: public; Owner: desyl
--

CREATE TYPE public.binding AS ENUM (
    'GLOBAL',
    'WEAK',
    ''
);


ALTER TYPE public.binding OWNER TO desyl;

--
-- Name: exec_format; Type: TYPE; Schema: public; Owner: desyl
--

CREATE TYPE public.exec_format AS ENUM (
    'elf',
    'pe',
    'macho'
);


ALTER TYPE public.exec_format OWNER TO desyl;

--
-- Name: exec_type; Type: TYPE; Schema: public; Owner: desyl
--

CREATE TYPE public.exec_type AS ENUM (
    'object',
    'executable',
    'shared_library'
);


ALTER TYPE public.exec_type OWNER TO desyl;

--
-- Name: linkage; Type: TYPE; Schema: public; Owner: desyl
--

CREATE TYPE public.linkage AS ENUM (
    'dynamic',
    'static'
);


ALTER TYPE public.linkage OWNER TO desyl;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: binaries; Type: TABLE; Schema: public; Owner: desyl
--

CREATE TABLE public.binaries (
    id integer NOT NULL,
    path character varying,
    name character varying,
    optimisation character varying(4),
    linkage public.linkage,
    compiler character varying,
    arch public.architecture NOT NULL,
    sha256 bytea NOT NULL,
    stripped boolean,
    size bigint NOT NULL,
    language character varying(8),
    dynamic_imports jsonb,
    version character varying,
    bin_format public.exec_format NOT NULL,
    bin_type public.exec_type NOT NULL
);


ALTER TABLE public.binaries OWNER TO desyl;

--
-- Name: binary_functions_id_seq; Type: SEQUENCE; Schema: public; Owner: desyl
--

CREATE SEQUENCE public.binary_functions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.binary_functions_id_seq OWNER TO desyl;

--
-- Name: binary_id_seq; Type: SEQUENCE; Schema: public; Owner: desyl
--

CREATE SEQUENCE public.binary_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.binary_id_seq OWNER TO desyl;

--
-- Name: binary_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: desyl
--

ALTER SEQUENCE public.binary_id_seq OWNED BY public.binaries.id;


--
-- Name: embedding_binnet; Type: TABLE; Schema: public; Owner: desyl
--

CREATE TABLE public.embedding_binnet (
    function_id integer NOT NULL,
    cat_embedding bytea,
    categorical_vector bytea,
    quantitative_vector bytea,
    quant_embedding bytea,
    embedding bytea
);


ALTER TABLE public.embedding_binnet OWNER TO desyl;

--
-- Name: executables; Type: VIEW; Schema: public; Owner: desyl
--

CREATE VIEW public.executables AS
 SELECT binaries.id,
    binaries.path,
    binaries.name,
    binaries.optimisation,
    binaries.linkage,
    binaries.compiler,
    binaries.arch,
    binaries.sha256,
    binaries.stripped,
    binaries.size,
    binaries.language,
    binaries.dynamic_imports,
    binaries.version,
    binaries.bin_format,
    binaries.bin_type
   FROM public.binaries
  WHERE (binaries.bin_type = 'executable'::public.exec_type);


ALTER TABLE public.executables OWNER TO desyl;

--
-- Name: functions; Type: TABLE; Schema: public; Owner: desyl
--

CREATE TABLE public.functions (
    id integer DEFAULT nextval('public.binary_functions_id_seq'::regclass) NOT NULL,
    binary_id integer,
    real_name character varying,
    name character varying,
    local_stack_bytes bigint,
    arguments jsonb,
    num_args integer,
    heap_arguments jsonb,
    returns character varying,
    tls_arguments jsonb,
    tainted_flows jsonb,
    cfg character varying,
    callers jsonb,
    callees jsonb,
    vex jsonb,
    closure jsonb,
    sha256 bytea,
    opcode_hash bytea,
    asm_hash bytea,
    size integer,
    binding public.binding,
    vaddr numeric,
    tainted_args jsonb,
    tainted_args_closure jsonb,
    callgraph_node_embedding bytea,
    icfg_embedding bytea,
    data_refs jsonb,
    opcode_minhash bytea,
    imported_data_refs jsonb,
    signature character varying,
    noreturn boolean
);




ALTER TABLE public.functions OWNER TO desyl;

--
-- Name: executable_functions; Type: VIEW; Schema: public; Owner: desyl
--

CREATE VIEW public.executable_functions AS
 SELECT functions.id,
    functions.binary_id,
    functions.real_name,
    functions.name,
    functions.local_stack_bytes,
    functions.arguments,
    functions.num_args,
    functions.heap_arguments,
    functions.returns,
    functions.tls_arguments,
    functions.tainted_flows,
    functions.cfg,
    functions.callers,
    functions.callees,
    functions.vex,
    functions.closure,
    functions.sha256,
    functions.opcode_hash,
    functions.asm_hash,
    functions.size,
    functions.binding,
    functions.vaddr,
    functions.tainted_args,
    functions.tainted_args_closure,
    functions.callgraph_node_embedding,
    functions.icfg_embedding,
    functions.data_refs,
    functions.opcode_minhash,
    functions.imported_data_refs,
    functions.signature,
    functions.noreturn
   FROM public.functions
  WHERE (functions.binary_id IN ( SELECT executables.id
           FROM public.executables));


ALTER TABLE public.executable_functions OWNER TO desyl;

--
-- Name: libraries; Type: VIEW; Schema: public; Owner: desyl
--

CREATE VIEW public.libraries AS
 SELECT binaries.id,
    binaries.path,
    binaries.name,
    binaries.optimisation,
    binaries.linkage,
    binaries.compiler,
    binaries.arch,
    binaries.sha256,
    binaries.stripped,
    binaries.size,
    binaries.language,
    binaries.dynamic_imports,
    binaries.version,
    binaries.bin_format,
    binaries.bin_type
   FROM public.binaries
  WHERE (binaries.bin_type = 'shared_library'::public.exec_type);


ALTER TABLE public.libraries OWNER TO desyl;

--
-- Name: library_functions; Type: VIEW; Schema: public; Owner: desyl
--

CREATE VIEW public.library_functions AS
 SELECT functions.id,
    functions.binary_id,
    functions.real_name,
    functions.name,
    functions.local_stack_bytes,
    functions.arguments,
    functions.num_args,
    functions.heap_arguments,
    functions.returns,
    functions.tls_arguments,
    functions.tainted_flows,
    functions.cfg,
    functions.callers,
    functions.callees,
    functions.vex,
    functions.closure,
    functions.sha256,
    functions.opcode_hash,
    functions.asm_hash,
    functions.size,
    functions.binding,
    functions.vaddr,
    functions.tainted_args,
    functions.tainted_args_closure,
    functions.callgraph_node_embedding,
    functions.icfg_embedding,
    functions.data_refs,
    functions.opcode_minhash,
    functions.imported_data_refs,
    functions.signature,
    functions.noreturn
   FROM public.functions
  WHERE (functions.binary_id IN ( SELECT libraries.id
           FROM public.libraries));


ALTER TABLE public.library_functions OWNER TO desyl;

--
-- Name: objects; Type: VIEW; Schema: public; Owner: desyl
--

CREATE VIEW public.objects AS
 SELECT binaries.id,
    binaries.path,
    binaries.name,
    binaries.optimisation,
    binaries.linkage,
    binaries.compiler,
    binaries.arch,
    binaries.sha256,
    binaries.stripped,
    binaries.size,
    binaries.language,
    binaries.dynamic_imports,
    binaries.version,
    binaries.bin_format,
    binaries.bin_type
   FROM public.binaries
  WHERE (binaries.bin_type = 'object'::public.exec_type);


ALTER TABLE public.objects OWNER TO desyl;

--
-- Name: object_functions; Type: VIEW; Schema: public; Owner: desyl
--

CREATE VIEW public.object_functions AS
 SELECT functions.id,
    functions.binary_id,
    functions.real_name,
    functions.name,
    functions.local_stack_bytes,
    functions.arguments,
    functions.num_args,
    functions.heap_arguments,
    functions.returns,
    functions.tls_arguments,
    functions.tainted_flows,
    functions.cfg,
    functions.callers,
    functions.callees,
    functions.vex,
    functions.closure,
    functions.sha256,
    functions.opcode_hash,
    functions.asm_hash,
    functions.size,
    functions.binding,
    functions.vaddr,
    functions.tainted_args,
    functions.tainted_args_closure,
    functions.callgraph_node_embedding,
    functions.icfg_embedding,
    functions.data_refs,
    functions.opcode_minhash,
    functions.imported_data_refs,
    functions.signature,
    functions.noreturn
   FROM public.functions
  WHERE (functions.binary_id IN ( SELECT objects.id
           FROM public.objects));


ALTER TABLE public.object_functions OWNER TO desyl;

--
-- Name: binaries id; Type: DEFAULT; Schema: public; Owner: desyl
--

ALTER TABLE ONLY public.binaries ALTER COLUMN id SET DEFAULT nextval('public.binary_id_seq'::regclass);


--
-- Name: functions binary_functions_pkey; Type: CONSTRAINT; Schema: public; Owner: desyl
--

ALTER TABLE ONLY public.functions
    ADD CONSTRAINT binary_functions_pkey PRIMARY KEY (id);


--
-- Name: binaries binary_pkey; Type: CONSTRAINT; Schema: public; Owner: desyl
--

ALTER TABLE ONLY public.binaries
    ADD CONSTRAINT binary_pkey PRIMARY KEY (id);


--
-- Name: binaries binary_unique_path; Type: CONSTRAINT; Schema: public; Owner: desyl
--

ALTER TABLE ONLY public.binaries
    ADD CONSTRAINT binary_unique_path UNIQUE (path);


--
-- Name: embedding_binnet embeddings_xfl_pkey; Type: CONSTRAINT; Schema: public; Owner: desyl
--

ALTER TABLE ONLY public.embedding_binnet
    ADD CONSTRAINT embeddings_xfl_pkey PRIMARY KEY (function_id);


--
-- Name: embedding_binnet unique_function_id; Type: CONSTRAINT; Schema: public; Owner: desyl
--

ALTER TABLE ONLY public.embedding_binnet
    ADD CONSTRAINT unique_function_id UNIQUE (function_id);


--
-- Name: binaries unique_hash; Type: CONSTRAINT; Schema: public; Owner: desyl
--

ALTER TABLE ONLY public.binaries
    ADD CONSTRAINT unique_hash UNIQUE (sha256);


--
-- Name: arguments; Type: INDEX; Schema: public; Owner: desyl
--

CREATE INDEX arguments ON public.functions USING btree (arguments);


--
-- Name: binary_function_opcode_index; Type: INDEX; Schema: public; Owner: desyl
--

CREATE INDEX binary_function_opcode_index ON public.functions USING hash (opcode_hash);


--
-- Name: binary_function_sha256_index; Type: INDEX; Schema: public; Owner: desyl
--

CREATE INDEX binary_function_sha256_index ON public.functions USING hash (sha256);


--
-- Name: binary_function_vaddr_index; Type: INDEX; Schema: public; Owner: desyl
--

CREATE INDEX binary_function_vaddr_index ON public.functions USING brin (binary_id, vaddr);


--
-- Name: cfg_index; Type: INDEX; Schema: public; Owner: desyl
--

CREATE INDEX cfg_index ON public.functions USING hash (cfg);


--
-- Name: jumpkinds_index; Type: INDEX; Schema: public; Owner: desyl
--

CREATE INDEX jumpkinds_index ON public.functions USING hash (((vex ->> 'jumpkinds'::text)));


--
-- Name: name_index; Type: INDEX; Schema: public; Owner: desyl
--

CREATE INDEX name_index ON public.functions USING btree (name);


--
-- Name: operations_index; Type: INDEX; Schema: public; Owner: desyl
--

CREATE INDEX operations_index ON public.functions USING hash (((vex ->> 'operations'::text)));


--
-- Name: functions binary_functions_binary_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desyl
--

ALTER TABLE ONLY public.functions
    ADD CONSTRAINT binary_functions_binary_id_fkey FOREIGN KEY (binary_id) REFERENCES public.binaries(id);


--
-- Name: embedding_binnet embeddings_xfl_function_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: desyl
--

ALTER TABLE ONLY public.embedding_binnet
    ADD CONSTRAINT embeddings_xfl_function_id_fkey FOREIGN KEY (function_id) REFERENCES public.functions(id);


--
-- PostgreSQL database dump complete
--

ALTER TYPE public.binding ADD VALUE 'UNKNOWN';
ALTER TYPE public.binding ADD VALUE 'LOCAL'; 
ALTER TABLE public.functions ADD sse jsonb;


CREATE TABLE public.library_p (
    id integer NOT NULL,
    path character varying,
    name character varying
);


ALTER TABLE public.library_p OWNER TO desyl;


CREATE SEQUENCE public.library_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.library_id_seq OWNER TO desyl;



ALTER SEQUENCE public.library_id_seq OWNED BY public.library_p.id;

CREATE TABLE public.library_prototypes (
    id integer NOT NULL,
    library integer NOT NULL,
    name character varying,
    real_name character varying,
    local_stack_bytes bigint,
    arguments jsonb,
    num_args integer,
    heap_arguments jsonb,
    return character varying,
    tls_arguments jsonb
);


ALTER TABLE public.library_prototypes OWNER TO desyl;


CREATE SEQUENCE public.library_prototypes_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.library_prototypes_id_seq OWNER TO desyl;

ALTER SEQUENCE public.library_prototypes_id_seq OWNED BY public.library_prototypes.id;


CREATE SEQUENCE public.library_prototypes_library_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER TABLE public.library_prototypes_library_seq OWNER TO desyl;


ALTER SEQUENCE public.library_prototypes_library_seq OWNED BY public.library_prototypes.library;


ALTER TABLE ONLY public.library_p ALTER COLUMN id SET DEFAULT nextval('public.library_id_seq'::regclass);
ALTER TABLE ONLY public.library_prototypes ALTER COLUMN id SET DEFAULT nextval('public.library_prototypes_id_seq'::regclass);
ALTER TABLE ONLY public.library_prototypes ALTER COLUMN library SET DEFAULT nextval('public.library_prototypes_library_seq'::regclass);


ALTER TABLE ONLY public.library_p
    ADD CONSTRAINT library_pkey PRIMARY KEY (id);


ALTER TABLE ONLY public.library_prototypes
    ADD CONSTRAINT library_prototypes_pkey PRIMARY KEY (id);



ALTER TABLE ONLY public.library_p
    ADD CONSTRAINT unique_path UNIQUE (path);


CREATE INDEX ix_library_prototypes_regex_resolve ON public.library_prototypes USING gin (to_tsvector('english'::regconfig, (name)::text));

ALTER TABLE ONLY public.library_prototypes
    ADD CONSTRAINT library_prototypes_library_fkey FOREIGN KEY (library) REFERENCES public.library_p(id);



