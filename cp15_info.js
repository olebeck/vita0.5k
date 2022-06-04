// tbody is the table here: https://developer.arm.com/documentation/ddi0360/e/control-coprocessor-cp15/summary-of-cp15-instructions

function parse_instruction(instruction) {
    var parts = instruction.split(", ");
    var op = parts[0].toLowerCase();
    var args = parts.slice(1);
    return {op, args};
}

var output = "{\n";

for (const section of tbody.children) {
    const count = section.cells[0].children.length;
    for (let i = 0; i < count; i++) {
        const instruction = section.cells[0].children[i].textContent;
        const operation = section.cells[1].children[i]?.textContent;
        const reference = section.cells[2].children[i]?.textContent;

        const {op, args} = parse_instruction(instruction);

        output += `{"${op} ${args.join(" ")}", "${operation}"},\n`;
    }
    output += "\n";
}

output += "}\n";

console.log(output);