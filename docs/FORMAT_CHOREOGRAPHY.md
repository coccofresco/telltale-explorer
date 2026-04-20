# CHORE — Choreography Files (surface-level support)

Choreography files tie together animations, dialog, audio and cameras for
cutscenes and per-agent behaviours. The on-disk layout is a `MetaStream`
(ERTM) container wrapping a complex `Chore` struct with several nested
MetaClasses.

`inspect_chore.py` implements **surface-level** inspection only: it pulls
out the choreography's display name and the list of resource handles it
references (anims, scenes, audio, props). This is enough to navigate
1929 ep1 chores without a full MetaStream + MetaClass reflection reader.

A full decoder is not yet shipped — see "Roadmap" below.

## Top-level schema (TelltaleToolLib `Types/Chore.h`)

```cpp
struct Chore {
    String                             mName;
    Flags                              mFlags;
    float                              mLength;
    long                               mNumResources;
    long                               mNumAgents;
    PropertySet                        mEditorProps;
    String                             mChoreSceneFile;
    long                               mRenderDelay;
    LocalizeInfo                       mSynchronizedToLocalization;
    DependencyLoader<1>                mDependencies;
    ToolProps                          mToolProps;
    Map<Symbol, WalkPath>              mWalkPaths;
    DCArray<ChoreResource*>            mPtrResources;   // loop appended manually
    DCArray<ChoreAgent*>               mPtrAgents;      // loop appended manually
};

struct ChoreResource {
    long        mVersion;
    Symbol      mResName;
    float       mResLength;
    long        mPriority;
    Flags       mFlags;
    String      mResourceGroup;
    HandleBase  mhObject;
    Animation   mControlAnimation;
    DCArray<Block>       mBlocks;         // { float start, end; bool loop; float scale; }
    bool        mbNoPose, mbEmbedded, mbEnabled, mbIsAgentResource, ...
    PropertySet mResourceProperties;
    Map<Symbol, float>   mResourceGroupInclude;
    AutoActStatus        mAAStatus;
};

struct ChoreAgent {
    String                 mAgentName;
    Flags                  mFlags;
    DCArray<int>           mResources;       // indices into Chore::mPtrResources
    Attachment             mAttachment;      // attach-to-bone info
    ActorAgentBinding      mAABinding;
    Rule                   mAgentEnabledRule;
};
```

## What `inspect_chore.py` extracts

```python
from inspect_chore import inspect, ChoreSurface

c = inspect("path/to/file.chore")
c.name            # from the leading blocked String
c.handles         # every length-prefixed ASCII string with a known asset extension
                  # (anm, chore, scene, wav, prop, d3dtx, d3dmesh, …)
c.flags, c.length, c.num_resources, c.num_agents   # best-effort primitives
```

Handle scraping works by walking all `u32 strlen + strlen bytes` sequences
of printable ASCII that end with a known asset extension. This catches
every `Handle<Animation>` / `Handle<Chore>` / `Handle<AudioData>` buried
inside the nested sub-structures without needing to decode `PropertySet`,
`LocalizeInfo`, `DependencyLoader`, `ToolProps`, `WalkPath` or the
polymorphic `HandleObjectInfo` blob.

## ep1 coverage

- 1929 / 1929 chores scanned without errors
- 22 528 handles extracted
- 2 145 unique animation references (`*.anm`)
- Additional references: 2 582 `*.wav`, 2 013 `*.scene`, 1 175 `*.chore`,
  381 `*.prop`, 208 `*.d3dtx`

## Roadmap — full decoder

A complete `Chore` decoder requires:

1. A reusable `MetaStream` walker with `BeginBlock` / `EndBlock`
   traversal (we have size-prefix readers but no generic walker yet).
2. Per-class member serializers driven by `SerializedVersionInfo` — this
   includes `PropertySet`, `LocalizeInfo`, `DependencyLoader<1>`,
   `ToolProps`, and the polymorphic `PathBase` hierarchy for `WalkPath`.
3. Handling of embedded resources inside `ChoreResource::mhObject` whose
   concrete class varies per entry (`Animation`, `Chore`, `AudioData`,
   ...).

That's ~2 k lines of Python and is tracked as future work. For now,
surface extraction covers the most common navigation use case.
