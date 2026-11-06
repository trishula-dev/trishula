# EASE paper checklist

This checklist applies the EASE guidelines to the project's technical
research papers. Basis: the EASE Guidelines for Authors and Translators
(European Association of Science Editors, 2019 edition). The 2024 successor
volume, "Writing Your Research Paper: Tips From EASE Editors", carries the
same rules in a newer form.

## Scope boundary

- The EASE set covers the papers. The repo documents (README, spec pages,
  issue and PR bodies) follow ASD-STE100 instead.
- One rule set per artifact class. The papers keep the academic voice.
- STE100 sentence discipline stays available as the conversion tool when a
  paper sentence runs long during a fix.

## Papers under this checklist

- The paper sources live at the authoring points recorded in the
  paper-authoring skill (repo copy or workspace copy). The checklist file
  lands at each authoring point.
- A paper without a repository still gets the checklist beside its source.

## The pass (run in order)

1. Title. The title states the artifact class, the method, and the scope.
   The title stays specific.
2. Abstract. The abstract is informative. It names the problem, the
   method, the result, and the position. Target length: 200 to 300 words.
   The abstract carries no citations and no undefined abbreviations.
3. Keywords. One keywords line sits under the abstract. The separator is
   the middle dot.
4. Structure. The section order reads: introduction, background, method or
   architecture, results or positions, limitations, ethics, references.
5. Sections carry numbers. Cross-references cite the section number.
   Position words ("below", "above") do not appear.
6. Terminology. One term names one concept through the whole paper. Code
   names stay in code spans, spelled once.
7. Numbers and units. Numbers read as digits with the unit adjacent
   (7.64 MB, 1 in 5). Ranges read "from X to Y".
8. Citations. Every factual claim carries a citation or a measured number.
   The reference list matches the citation numbers one to one.
9. Ethics, authorship, and use. Every paper carries the statement from the
   template below.
10. Render audit. Re-render the paper. The audit prints a sane page count
    and resolves: TOC links, back-to-contents links on every page after
    the cover, PDF title and author metadata.

## Ethics statement - the template

*Authorship —* Shaineel Singh is the sole author and maintainer of this paper
(contact: shain.singh@owasp.org).

*Funding —* the author states the funding position of the work.

*Conflicts of interest —* the author states the conflict position of the
work.

*Authorised use —* papers that ship or describe attack tooling carry this
line: the tooling serves authorised security work only. Authorised work:
engagements with written authorisation, academic research, and defender
validation.

## Revision rule

- A pass lands as a new revision file. The pattern: `paper-rN+1.md` for
  the revision-numbered papers, draft `vN+1` for the version-numbered
  paper.
- The old file stays. The revision line records the date and the pass.
