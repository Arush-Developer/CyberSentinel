import { Notice } from "../components/ui";

const OFFICIAL = "official eval partition";

/** Says plainly when the replay is not the official pack, so rehearsal results can't pass as official. */
export function ReplayInputNotice({ input }: { input: string }) {
  if (input === OFFICIAL) return null;
  const rehearsal = input.includes("rehearsal");
  return (
    <Notice tone="warn" title={rehearsal ? "Rehearsal input with invented addresses" : "Not the official validation partition"}>
      {rehearsal
        ? "These are real flows, but their source and destination addresses were invented for testing. Results here show the mechanism, not expected performance."
        : `Replaying ${input}.`}
    </Notice>
  );
}
