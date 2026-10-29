-module(splitter).
-compile([no_auto_import, nowarn_ignored, nowarn_unused_vars, nowarn_unused_function, nowarn_nomatch, inline]).
-export([new/1, split/2, split_before/2, split_after/2, would_split/2, split_all/2]).
-export_type([splitter/0]).

-type splitter() :: any().

-spec new(list(binary())) -> splitter().
-doc(~" Create a new splitter for a given list of substrings.

 Substrings are matched for in the order the appear in the list, if one
 substring is the substring of another place it later in the list than the
 superstring.

 Empty strings are discarded, and an empty list will not split off any
 prefix.

 There is a small cost to creating a splitter, so if you are going to split
 a string multiple times, and you want as much performance as possible, then
 it is better to reuse the same splitter than to create a new one each time.
").
new(Substrings) ->
    _pipe = Substrings,
    _pipe@1 = gleam@list:filter(_pipe, fun(X) ->
        X /= ~""
    end),
    splitter_ffi:new(_pipe@1).

-spec split(splitter(), binary()) -> {binary(), binary(), binary()}.
-doc(~" Use the splitter to find the first substring in the input string, splitting
 the input string at that point.

 A tuple of three strings is returned:
 1. The string prefix before the split.
 2. The substring the string was split with.
 3. The string suffix after the split.

 If no substring was found then strings 2 and 3 will be empty, and string 1
 will be the whole input string.

 # Examples

 ```gleam
 let line_ends = splitter.new([\"\\n\", \"\\r\\n\"])

 splitter.split(line_ends, \"1. Bread\\n2. Milk\\n\")
 // -> #(\"1. Bread\", \"\\n\", \"2. Milk\\n\")

 splitter.split(line_ends, \"No end of line here!\")
 // -> #(\"No end of line here!\", \"\", \"\")
 ```
").
split(Splitter, String) ->
    splitter_ffi:split(Splitter, String).

-spec split_before(splitter(), binary()) -> {binary(), binary()}.
-doc(~" Use the splitter to find the first substring in the input string, splitting
 the input string before that point.

 A tuple of two strings is returned:
 1. The string prefix before the matched substring.
 2. The matched substring and the suffix after.

 If no substring was found then the suffix will be empty, and the prefix
 will be the whole input string.

 # Examples

 ```gleam
 let line_ends = splitter.new([\"\\n\", \"\\r\\n\"])

 splitter.split_before(line_ends, \"1. Bread\\n2. Milk\\n\")
 // -> #(\"1. Bread\", \"\\n2. Milk\\n\")

 splitter.split_before(line_ends, \"No end of line here!\")
 // -> #(\"No end of line here!\", \"\")
 ```
").
split_before(Splitter, String) ->
    splitter_ffi:split_before(Splitter, String).

-spec split_after(splitter(), binary()) -> {binary(), binary()}.
-doc(~" Use the splitter to find the first substring in the input string, splitting
 the input string after that point.

 A tuple of two strings is returned:
 1. The string prefix before and including the matched substring.
 2. The suffix after the matched substring.

 If no substring was found then the suffix will be empty, and the prefix
 will be the whole input string.

 # Examples

 ```gleam
 let line_ends = splitter.new([\"\\n\", \"\\r\\n\"])

 splitter.split_after(line_ends, \"1. Bread\\n2. Milk\\n\")
 // -> #(\"1. Bread\\n\", \"2. Milk\\n\")

 splitter.split_after(line_ends, \"No end of line here!\")
 // -> #(\"No end of line here!\", \"\")
 ```
").
split_after(Splitter, String) ->
    splitter_ffi:split_after(Splitter, String).

-spec would_split(splitter(), binary()) -> boolean().
-doc(~" Use the splitter to check whether any of the substrings are contained
 in the input string, without splitting the input string.

 Returns a bool value indicating whether a match was found in the input
 string.

 # Examples

 ```gleam
 let line_ends = splitter.new([\"\\n\", \"\\r\\n\"])

 splitter.would_split(line_ends, \"1. Bread\\n2. Milk\\n\")
 // -> True

 splitter.would_split(line_ends, \"No end of line here!\")
 // -> False
 ```
 ").
would_split(Splitter, String) ->
    splitter_ffi:would_split(Splitter, String).

-spec split_all(splitter(), binary()) -> list(binary()).
split_all(Splitter, String) ->
    splitter_ffi:split_all(Splitter, String).

