import { TableWrap } from "../components/ui";

export interface ConfusionData { labels: string[]; rows_true_columns_predicted: number[][] }

export function ConfusionMatrix({ matrix }: { matrix: ConfusionData }) {
  const max = Math.max(...matrix.rows_true_columns_predicted.flat());
  return (
    <TableWrap>
      <table className="text-xs num border-separate border-spacing-0.5">
        <thead>
          <tr><th className="text-left text-text-3 pr-2 font-normal">True ↓ Predicted →</th>{matrix.labels.map((l) => <th key={l} className="px-2 pb-1 text-text-3 font-normal text-[10px]">{l}</th>)}</tr>
        </thead>
        <tbody>
          {matrix.rows_true_columns_predicted.map((row, i) => (
            <tr key={i}>
              <th className="text-left pr-2 text-text-2 font-normal text-[11px]">{matrix.labels[i]}</th>
              {row.map((v, j) => {
                const intensity = v ? 0.12 + 0.88 * (Math.log(v + 1) / Math.log(max + 1)) : 0;
                const offDiagonal = i !== j && v > 0;
                return (
                  <td key={j} title={`True ${matrix.labels[i]}, predicted ${matrix.labels[j]}: ${v}`}
                    className={`px-3 py-2 text-center rounded-sm ${offDiagonal ? "ring-1 ring-warn" : ""}`}
                    style={{ background: v ? `rgba(57,135,229,${intensity})` : "#172236", color: intensity > 0.6 ? "#fff" : "#e8edf5" }}>
                    {v.toLocaleString("en-IN")}
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
    </TableWrap>
  );
}
