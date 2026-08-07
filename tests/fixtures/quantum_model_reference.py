#!/usr/bin/env python3
"""Эталон адаптивной модели Quantum — независимая проверка порта.

**Зачем этот файл лежит в репозитории.** Его вывод вбит руками в тест
`the_model_matches_the_reference_after_hundreds_of_rescales`
(`src/vendor/cab/quantum.rs`). Без генератора те таблицы нечем пересчитать и
нечем объяснить, откуда они взялись.

Почему таблицы вообще нужны: пересортировка модели срабатывает на каждом
пятидесятом пересчёте частот, а все существующие Quantum-архивы — сотни байт и
до неё не доходят. Побайтная сверка с `cabextract` эту ветвь не покрывает
(проверено мутацией: замена обменной сортировки на `sort_by_key` сверку
проходит). Поэтому ветвь сторожится сравнением с эталоном.

**Эталон выведен из C-кода libmspack** (`mspack/qtmd.c`,
`qtmd_update_model`), тогда как проверяемый Rust — из Objective-C кода
XADMaster. Две независимые головы; согласие между ними что-то значит.

Запуск: `python3 tests/fixtures/quantum_model_reference.py` — печатает готовые
строки для таблицы `cases` в тесте.
"""

def init(entries):
    # syms[i] = [symbol, cumfreq]; последний элемент — страж
    syms = [[i, entries - i] for i in range(entries)]
    syms.append([0, 0])
    return {"entries": entries, "shiftsleft": 4, "syms": syms}


def update(model, i):
    """GET_SYMBOL's tail: +8 на всё до i, затем при переполнении — пересчёт."""
    syms = model["syms"]
    while i > 0:
        i -= 1
        syms[i][1] += 8
    if syms[0][1] <= 3800:
        return

    model["shiftsleft"] -= 1
    if model["shiftsleft"]:
        for k in range(model["entries"] - 1, -1, -1):
            syms[k][1] >>= 1
            if syms[k][1] <= syms[k + 1][1]:
                syms[k][1] = syms[k + 1][1] + 1
    else:
        model["shiftsleft"] = 50
        for k in range(model["entries"]):
            syms[k][1] = (syms[k][1] - syms[k + 1][1] + 1) >> 1
        # Именно обменная сортировка: порядок при равных частотах — часть формата
        for a in range(model["entries"] - 1):
            for b in range(a + 1, model["entries"]):
                if syms[a][1] < syms[b][1]:
                    syms[a], syms[b] = syms[b], syms[a]
        for k in range(model["entries"] - 1, -1, -1):
            syms[k][1] += syms[k + 1][1]


# Детерминированная последовательность: линейный конгруэнтный генератор,
# чтобы её можно было слово в слово повторить в Rust.
def run(entries, steps):
    m = init(entries)
    state = 12345
    rescales = 0
    prev = m["shiftsleft"]
    for _ in range(steps):
        state = (state * 1103515245 + 12345) & 0x7FFFFFFF
        idx = 1 + state % entries          # индекс из поиска символа: 1..entries
        update(m, idx)
        if m["shiftsleft"] != prev:
            rescales += 1
        prev = m["shiftsleft"]
    return m, rescales


for entries, steps in ((7, 60000), (64, 200000), (42, 120000)):
    m, rescales = run(entries, steps)
    flat = ", ".join(f"({s[0]}, {s[1]})" for s in m["syms"])
    print(f"// entries={entries}, шагов={steps}, пересчётов={rescales}, shiftsleft={m['shiftsleft']}")
    print(f"({entries}, {steps}, {m['shiftsleft']}, &[{flat}]),")
    print()
