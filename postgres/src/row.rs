// Copyright 2026, Shiguredo Inc.
// SPDX-License-Identifier: Apache-2.0

//! 結果 1 行の型付き取得。
//!
//! 列番号または列名から値を取り出し、Rust の型へ変換する。
//! 変換は [`std::convert::TryFrom`] を使うため、独自の変換を実装する場合も
//! 新しいトレイトを定義する必要はない。

use crate::converters::Value;
use crate::error::{Error, Result};
use crate::protocol::FieldDescription;
use std::sync::Arc;

/// クエリ結果の 1 行。
///
/// 列の並びは結果セットのフィールド順で、NULL は [`Value::Null`] として保持する。
#[derive(Debug, Clone)]
pub struct Row {
    /// 結果セットのフィールド情報。同じ結果セットの行どうしで共有する。
    fields: Arc<[FieldDescription]>,
    values: Vec<Value>,
}

impl Row {
    /// 行を組み立てる。
    ///
    /// `fields` と `values` の要素数は一致している必要がある。
    pub(crate) fn new(fields: Arc<[FieldDescription]>, values: Vec<Value>) -> Self {
        debug_assert_eq!(
            fields.len(),
            values.len(),
            "Row fields and values must have the same length"
        );
        Self { fields, values }
    }

    /// 列数を返す。
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// 列がないかどうか。
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// 列名を列番号の順に返す。
    pub fn column_names(&self) -> impl Iterator<Item = &str> {
        self.fields.iter().map(|field| field.name.as_str())
    }

    /// 列名に対応する列番号を返す。
    ///
    /// PostgreSQL は引用符で囲まない識別子を小文字に畳むため、
    /// 列名の比較は大文字と小文字を区別する。
    pub fn column_index(&self, name: &str) -> Option<usize> {
        self.fields.iter().position(|field| field.name == name)
    }

    /// 列番号に対応する列名を返す。
    pub fn column_name(&self, index: usize) -> Option<&str> {
        self.fields.get(index).map(|field| field.name.as_str())
    }

    /// 列番号に対応する値を参照する。
    ///
    /// 範囲外の列番号の場合は `None` を返す。
    pub fn value(&self, index: usize) -> Option<&Value> {
        self.values.get(index)
    }

    /// 列名に対応する値を参照する。
    ///
    /// 列名が存在しない場合はエラーを返す。
    pub fn value_by_name(&self, name: &str) -> Result<&Value> {
        let index = self
            .column_index(name)
            .ok_or_else(|| Error::interface(format!("Column `{name}` does not exist")))?;
        Ok(&self.values[index])
    }

    /// 列番号から値を取り出し、指定した型へ変換する。
    ///
    /// 列番号が範囲外の場合、NULL の場合、型が一致しない場合はエラーを返す。
    /// NULL を許す場合は [`Row::get_opt`] を使う。
    pub fn get<T>(&self, index: usize) -> Result<T>
    where
        T: for<'a> TryFrom<&'a Value, Error = Error>,
    {
        let value = self
            .value(index)
            .ok_or_else(|| Error::interface(format!("Column index {index} is out of range")))?;
        T::try_from(value).map_err(|error| {
            Error::interface(format!(
                "Column {index} ({}): {}",
                self.column_name(index).unwrap_or(""),
                error
            ))
        })
    }

    /// 列番号から値を取り出し、NULL を `None` として返す。
    ///
    /// NULL 以外は [`Row::get`] と同じ規則で変換する。
    pub fn get_opt<T>(&self, index: usize) -> Result<Option<T>>
    where
        T: for<'a> TryFrom<&'a Value, Error = Error>,
    {
        let value = self
            .value(index)
            .ok_or_else(|| Error::interface(format!("Column index {index} is out of range")))?;
        if matches!(value, Value::Null) {
            return Ok(None);
        }
        self.get(index).map(Some)
    }

    /// 列名から値を取り出し、指定した型へ変換する。
    pub fn get_by_name<T>(&self, name: &str) -> Result<T>
    where
        T: for<'a> TryFrom<&'a Value, Error = Error>,
    {
        let index = self
            .column_index(name)
            .ok_or_else(|| Error::interface(format!("Column `{name}` does not exist")))?;
        self.get(index)
    }

    /// 列名から値を取り出し、NULL を `None` として返す。
    pub fn get_opt_by_name<T>(&self, name: &str) -> Result<Option<T>>
    where
        T: for<'a> TryFrom<&'a Value, Error = Error>,
    {
        let index = self
            .column_index(name)
            .ok_or_else(|| Error::interface(format!("Column `{name}` does not exist")))?;
        self.get_opt(index)
    }

    /// 行が保持する値をすべて返す。
    pub fn into_values(self) -> Vec<Value> {
        self.values
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// テスト用のフィールド記述を組み立てる。
    fn field(name: &str, type_oid: u32) -> FieldDescription {
        FieldDescription {
            name: name.to_string(),
            table_oid: 0,
            column_attr: 0,
            type_oid,
            type_size: -1,
            type_modifier: -1,
            format: 0,
        }
    }

    /// 列番号と列名の両方から型付きで取得できることを確認する。
    #[test]
    fn test_get_by_index_and_name() {
        let row = Row::new(
            vec![field("id", 23), field("name", 25), field("note", 25)].into(),
            vec![
                Value::Int4(42),
                Value::Text("postgres".to_string()),
                Value::Null,
            ],
        );

        assert_eq!(row.len(), 3, "列数が一致しません");
        assert_eq!(row.get::<i32>(0).expect("整数を取得できません"), 42);
        assert_eq!(
            row.get_by_name::<String>("name")
                .expect("文字列を取得できません"),
            "postgres"
        );
        assert!(
            row.get_opt::<String>(2)
                .expect("NULL を取得できません")
                .is_none(),
            "NULL が None になりません"
        );
        assert_eq!(row.column_index("name"), Some(1), "列番号が一致しません");
        assert_eq!(
            row.column_index("missing"),
            None,
            "存在しない列が見つかりました"
        );
    }

    /// 範囲外の列番号と存在しない列名がエラーになることを確認する。
    #[test]
    fn test_missing_column_is_an_error() {
        let row = Row::new(vec![field("id", 23)].into(), vec![Value::Int4(1)]);

        assert!(row.get::<i32>(1).is_err(), "範囲外の列番号が受理されました");
        assert!(
            row.get_by_name::<i32>("missing").is_err(),
            "存在しない列名が受理されました"
        );
        assert!(
            row.get::<String>(0).is_err(),
            "型の異なる変換が成功しました"
        );
        assert!(row.get::<bool>(0).is_err(), "型の異なる変換が成功しました");
    }
}
