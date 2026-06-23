\# ✅ ✅ FULL SYSTEM SPEC



\*\*\*



\# \*\*1. Overview / System Description\*\*



The application is an \*\*offline attorney review and evidence preparation system\*\* for exploring communication records (SMS, MMS, email) and associated attachments.



The system enables users to:



\* quickly locate relevant communications

\* understand those communications in context

\* inspect complete message and attachment details

\* generate consistent, print-ready evidence documents



The system is:



\* fully offline (single HTML bundle)

\* deterministic (no runtime processing)

\* read-only



\*\*\*



\# \*\*2. Core Concepts\*\*



\*\*\*



\## ✅ Unified Timeline



All communication (SMS, MMS, email) is displayed in a single chronological stream.



\*\*\*



\## ✅ Contextual Search



Search results are displayed within surrounding chronological context (“context slices”), not as isolated messages.



\*\*\*



\## ✅ Context Slices



Each result appears as:



```

\[context before]



✅ MATCH



\[context after]



──────────── skipped N messages \[Show more] ─────────────

```



\*\*\*



\### ✅ Slice Separator



\* centered horizontally

\* visually distinct with divider line

\* clearly separates independent slices



\*\*\*



\## ✅ Source-Aware Rendering



Messages are rendered differently based on type:



\* SMS / MMS → conversational bubbles

\* Email → structured preview blocks



\*\*\*



\## ✅ Attachment Handling



Attachments are context-dependent:



\### SMS / MMS



\* attachments may appear inline as independent bubbles



\### Email



\* attachments are not standalone

\* shown only as indicators

\* full content visible in detail pane



\*\*\*



\## ✅ Pane Separation



| Pane  | Purpose                              |

| ----- | ------------------------------------ |

| Left  | discovery + contextual understanding |

| Right | detailed inspection                  |



\*\*\*



\*\*\*



\# \*\*3. Top Section (Global Controls)\*\*



\*\*\*



\## ✅ Search



\* primary interaction

\* operates across:

&#x20; \* message body

&#x20; \* email subject

&#x20; \* attachment filename

&#x20; \* selected metadata



\*\*\*



\## ✅ Filters



\* hidden by default

\* revealed via control (e.g., “Add Filter”)



Possible filters:



\* source

\* direction

\* has attachments

\* date range



\*\*\*



\## ✅ Actions



All actions grouped under:



```

\[Print ▾]

```



\*\*\*



\### ✅ Available Actions



\* Print Current Message

\* Print Results

\* Print Summary

\* Print Full Packet



\*\*\*



\### ✅ Behavior



\* actions depend on:

&#x20; \* selected message

&#x20; \* filtered dataset

&#x20; \* current view



\*\*\*



\*\*\*



\# \*\*4. Views\*\*



\*\*\*



\## ✅ 4.1 Messages View



Purpose:



> fast scanning



\*\*\*



\### ✅ Behavior



\* flat list

\* one row per message

\* no contextual expansion



\*\*\*



\*\*\*



\## ✅ 4.2 Timeline View



Purpose:



> contextual understanding



\*\*\*



\### ✅ Behavior



\* renders contextual slices

\* chronological ordering

\* mixed message types



\*\*\*



\### ✅ Rendering Types



\* SMS (bubble)

\* MMS (bubble with attachments)

\* Email (compact block)



\*\*\*



\*\*\*



\# \*\*5. Left Pane (Search Results)\*\*



\*\*\*



\## ✅ Messages View



\* compact list

\* minimal metadata

\* scan-first design



\*\*\*



\## ✅ Timeline View



Displays contextual slices.



\*\*\*



\### ✅ Slice Structure



```

\[n previous messages]



✅ MATCH



\[n next messages]



──────────── skipped X messages ────────────

```



\*\*\*



\### ✅ Rules



\* ordered by time

\* thread context preserved

\* slices grouped visually but not reordered



\*\*\*



\### ✅ Expansion



Click:



```

Show more

```



→ reveals small number of messages (incremental)  

→ does not expand entire thread



\*\*\*



\*\*\*



\# \*\*6. Right Pane (Detail View)\*\*



\*\*\*



\## ✅ Content (Visible by Default)



\* timestamp

\* sender / recipients

\* full message body

\* attachments (inline where applicable)



\*\*\*



\## ✅ Collapsed Sections



```

▸ Citation

▸ Evidence Integrity

▸ Metadata

▸ Thread Context

```



\*\*\*



\## ✅ Attachment Actions



Per attachment:



```

\[Open Original]   \[Open Exhibit PDF]

```



\*\*\*



\## ✅ Interaction



\* clicking any message updates panel

\* left pane scroll remains unchanged



\*\*\*



\*\*\*



\# \*\*7. Search \& Filter Logic\*\*



\*\*\*



\## ✅ Direct Matching



Search matches:



\* message body

\* email subject

\* attachment filename

\* metadata (optional)



\*\*\*



\## ✅ Contextual Matching (Attachments Only)



An attachment is a match if:



```

Direct match

OR

A nearby message (within N) matches

```



\*\*\*



\### ✅ N Value



```

N = 2–5 (recommended: 3)

```



\*\*\*



\## ✅ Important Clarification



\* messages do not require contextual matching

\* timeline rendering naturally preserves context



\*\*\*



\*\*\*



\# \*\*8. Rendering Rules\*\*



\*\*\*



\## ✅ SMS / MMS Rendering



\* bounded max width

\* rounded bubbles

\* inbound = left aligned

\* outbound = right aligned

\* distinct background colors



\*\*\*



\## ✅ Email Rendering



Full-width block (NOT bubble), exactly 3 lines:



```

From                                         \[date + time]



Subject (secondary emphasis)



Preview snippet (muted)

```



\*\*\*



\### ✅ Attachment Indicator



\* small icon or badge

\* does not replace timestamp



\*\*\*



\## ✅ Match Highlighting



\* applied to full message container

\* includes padding area

\* consistent across types



\*\*\*



\## ✅ Selected Message



\* subtle highlight

\* must not conflict with match highlight



\*\*\*



\*\*\*



\# \*\*9. Interaction Rules\*\*



\*\*\*



\## ✅ Selection



Click message:



\* updates detail pane

\* does not re-render results



\*\*\*



\## ✅ Expansion



\* incremental

\* bounded (e.g., +5 messages per click)



\*\*\*



\*\*\*



\# \*\*10. Print \& Output Model\*\*



\*\*\*



\## ✅ Core Principle



Printing is based on a normalized representation of all attachments.



\*\*\*



\## ✅ Print Modes



\*\*\*



\### Mode A: Inline



\* images rendered inline

\* PDFs replaced with exhibit references



\*\*\*



\### Mode B: Appendix (Exhibits)



\* all attachments rendered separately

\* messages contain references only



\*\*\*



\## ✅ Attachment Representation



All attachments converted into:



```

\[cover page image]

\[content page images]

```



\*\*\*



\*\*\*



\# \*\*11. Render Pipeline\*\*



\*\*\*



\## ✅ Pipeline Flow



```

Data → Normalize → Layout Model → HTML Render → Print

```



\*\*\*



\## ✅ Attachment Normalization



\### Images



```

cover + image

```



\*\*\*



\### PDFs



```

PDF → image pages

cover + page images

```



\*\*\*



\## ✅ Final Structure



Everything is rendered as images for print.



\*\*\*



\*\*\*



\# \*\*12. Print Layout \& CSS\*\*



\*\*\*



\## ✅ Page Setup



\* Letter (default)

\* 0.75–1 inch margins



\*\*\*



\## ✅ Layout



\* single column

\* centered content

\* max-width \\\~800–900px



\*\*\*



\## ✅ Message Blocks



\* header + body

\* avoid page splitting



\*\*\*



\## ✅ Attachment Pages



\* one attachment page = one printed page



\*\*\*



\## ✅ PDF Fidelity Rule



```

1 PDF page = 1 printed page

```



\*\*\*



\### ✅ CSS



```

.page {

&#x20; page-break-before: always;

&#x20; page-break-after: always;

&#x20; page-break-inside: avoid;

}

```



\*\*\*



\## ✅ Appendix Layout



```

\--- APPENDIX ---



Exhibit A-001

\[cover]

\[pages]

```



\*\*\*



\## ✅ Summary Print



```

| Date | Sender | Snippet | Exhibit |

```



Optionally followed by appendix.



\*\*\*



\## ✅ Print CSS



\* hide UI elements

\* enforce page breaks

\* use print-safe styling



\*\*\*



\*\*\*



\# ✅ ✅ FINAL SUMMARY



\*\*\*



\## You have built:



\### ✅ A unified communication timeline system



\### ✅ Context-aware search model



\### ✅ Source-aware rendering engine



\### ✅ Deterministic attachment normalization pipeline



\### ✅ Multi-mode print system



\### ✅ Full document generation pipeline



\*\*\*



\## The system now cleanly supports:



\* discovery (Messages View)

\* understanding (Timeline View)

\* inspection (Detail Pane)

\* evidence generation (Print Pipeline)



