Talkyard Naming Notes
==========================

`ttt` means Test the test. That is, some [assertion in a test] that doesn't test
the real Talkyard code — instead, it tests the test code. (There's no `tttt`)


### Categories

Each forum:

Root category —> Main categories —> Sub categories —> (Sub sub categories? or not?)

A main category is called "Main", not "Top", because "top" could be
incorrectly interpreted as "popular".

Root categories are Talkyard internal things — end users never see them;
they never see the phrase "Root category".



### Database tables, columns etc

Table names ends with `_t`, e.g. `links_t`.
Column names end with `_c`, e.g. `site_id_c`.

Otherwise it'd take long to find all occurrences of, for example, the links table:
if you search for "links" you find 99% off-topic matches,
but "links_t" gives you close to 100% on-topic search results.
Also, now you can just type: `link_url_c` without explaining that
it's a database column — the other Ty devs willl know,
since ends with `_c`. And can find it instantly in the database docs.

"Participant" is abbreviated with "pp" [NO "pat" instead! 2020-09],
or "..._by". E.g. `links_t.to_pp_id_c` [NO! shall be `to_pat_id_c` instead] means
a link to the participant with the id in the `to_pat_id_c` column.
Or e.g. `written_by_id_c`.

Constraints and indexes: (`tablename_x_...` nicely aligns the names if you
type `\d tablename` in psql).

 - Primary keys: `tablename_p` or `tablename_p_column1_col2_...`.
 - Foreign keys: `tablename_r_othertable` or `table_col1_col2_r_othertable`
   ('r' means "references").
 - Check constraints: `tablename_c_columnname` e.g. `linkpreviews_c_linkurl_len` — checks the
   length of the `link_previews_t.link_url_c` column.
 - Unique indexes: `tablename_u_col1_col2_etc`.
 - Other indexes: `tablename_i_col1_col2_etc`.

Don't include `site_id_c` in these names — the site id is always there, not interesting.
Instead, in the few cases where the site id is _not_ included, add `_g`,
for "global" index: `tablename_i_g_col1_col2` means `col1` and `col2` across all sites.


When adding a foreign key, always include a comment on the line above
about which index indexes that foreign key. Example:

```
create table links_t(
  ...
  to_post_id_c int,
  ...

  -- fk index: links_i_topostid
  constraint links_topostid_r_posts foreign key (site_id_c, to_post_id_c)
      references posts3 (site_id, unique_post_id),
  ...
);

...

create index links_i_topostid on links_t (site_id_c, to_post_id_c);
```

(Old table names look like `sometable3` for historical reasons,
but nowadays it's `sometable_t` instead.
And old columns: `site_id` or `post_id` but now it's `site_id_c` and `post_c` instead
— it's obvious that the columns are ids?)



### Cookies

Names like `tyCo...` so you can: `grep -r tyCo ./` and find all cookies.
(Right now it's `dwCo...`, should change to `tyCo`. RENAME )



### English language

It's "Create new topic", but "generate notifications":

- "Creating" things is something humans do, with a bit creativity. E.g. creating
  a new discussion topic. Or a chef might *create* a new dish — thereafter hen *makes*
  that dish every day. https://ell.stackexchange.com/a/76988/52

- "Generating" things is something computers can do, by following various algorithms.
  E.g. generating notifications about a new topic created by a human.
