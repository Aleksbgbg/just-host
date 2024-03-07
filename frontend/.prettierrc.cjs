module.exports = {
  plugins: [
    require.resolve("@trivago/prettier-plugin-sort-imports"),
    require.resolve("prettier-plugin-tailwindcss"),
  ],
  importOrder: ["^vue$", "^@?vue.*$", "<THIRD_PARTY_MODULES>", "^@/.*$"],
  importOrderSeparation: false,
  importOrderSortSpecifiers: true,
  printWidth: 100,
  tabWidth: 2,
  bracketSameLine: true,
};
