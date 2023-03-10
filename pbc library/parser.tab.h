/* A Bison parser, made by GNU Bison 2.3.  */

/* Skeleton interface for Bison's Yacc-like parsers in C

   Copyright (C) 1984, 1989, 1990, 2000, 2001, 2002, 2003, 2004, 2005, 2006
   Free Software Foundation, Inc.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2, or (at your option)
   any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

/* Tokens.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum yytokentype {
     END = 0,
     DEFINE = 258,
     TERMINATOR = 259,
     NUM = 260,
     ID = 261,
     LPAR = 262,
     RPAR = 263,
     LSQU = 264,
     RSQU = 265,
     LBRACE = 266,
     RBRACE = 267,
     COMMA = 268,
     COLON = 269,
     QUESTION = 270,
     GE = 271,
     LE = 272,
     T_GT = 273,
     LT = 274,
     NE = 275,
     EQ = 276,
     ASSIGN = 277,
     MINUS = 278,
     PLUS = 279,
     TIMES = 280,
     DIVIDE = 281,
     UMINUS = 282,
     POW = 283,
     UNKNOWN = 284
   };
#endif
/* Tokens.  */
#define END 0
#define DEFINE 258
#define TERMINATOR 259
#define NUM 260
#define ID 261
#define LPAR 262
#define RPAR 263
#define LSQU 264
#define RSQU 265
#define LBRACE 266
#define RBRACE 267
#define COMMA 268
#define COLON 269
#define QUESTION 270
#define GE 271
#define LE 272
#define T_GT 273
#define LT 274
#define NE 275
#define EQ 276
#define ASSIGN 277
#define MINUS 278
#define PLUS 279
#define TIMES 280
#define DIVIDE 281
#define UMINUS 282
#define POW 283
#define UNKNOWN 284




#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef int YYSTYPE;
# define yystype YYSTYPE /* obsolescent; will be withdrawn */
# define YYSTYPE_IS_DECLARED 1
# define YYSTYPE_IS_TRIVIAL 1
#endif

extern YYSTYPE yylval;

