import { Card, CardContent } from "@/components/ui/card";

/** The uniform placeholder for sections whose backend does not exist yet.
 *  Honest by design: it names the phase instead of showing invented data. */
export function Placeholder({ title }: { title: string }) {
  return (
    <Card className="rounded-xl border border-dashed border-border bg-card shadow-sm">
      <CardContent className="p-8 text-center">
        <div className="text-[15px] font-semibold text-foreground">{title}</div>
        <p className="mx-auto mt-1.5 max-w-md text-[12.5px] text-muted-foreground leading-relaxed">
          Coming in a later phase. This section needs backend subsystems that do
          not exist yet, so nothing is shown here rather than invented data.
        </p>
      </CardContent>
    </Card>
  );
}
