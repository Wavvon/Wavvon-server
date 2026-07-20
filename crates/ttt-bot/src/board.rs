//! Pure tic-tac-toe board logic -- no I/O, no async, fully unit-testable.
//! The bot is the sole authority over this state (bot-capability-layer.md
//! decision 4: "the hub stays dumb about games").

pub type Board = [Option<Symbol>; 9];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Symbol {
    X,
    O,
}

impl Symbol {
    pub fn other(self) -> Self {
        match self {
            Symbol::X => Symbol::O,
            Symbol::O => Symbol::X,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Symbol::X => "X",
            Symbol::O => "O",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum MoveError {
    OutOfRange,
    CellTaken,
    GameOver,
}

/// Validates and applies a single move. Turn ownership (is it really this
/// player's turn?) is checked by the caller against its own session state --
/// this function only knows about the board itself.
pub fn validate_and_apply(
    board: &mut Board,
    turn: Symbol,
    cell: usize,
    finished: bool,
) -> Result<(), MoveError> {
    if finished {
        return Err(MoveError::GameOver);
    }
    if cell >= 9 {
        return Err(MoveError::OutOfRange);
    }
    if board[cell].is_some() {
        return Err(MoveError::CellTaken);
    }
    board[cell] = Some(turn);
    Ok(())
}

const LINES: [[usize; 3]; 8] = [
    [0, 1, 2],
    [3, 4, 5],
    [6, 7, 8],
    [0, 3, 6],
    [1, 4, 7],
    [2, 5, 8],
    [0, 4, 8],
    [2, 4, 6],
];

pub fn winner(board: &Board) -> Option<Symbol> {
    for line in LINES {
        if let (Some(a), Some(b), Some(c)) = (board[line[0]], board[line[1]], board[line[2]]) {
            if a == b && b == c {
                return Some(a);
            }
        }
    }
    None
}

pub fn is_full(board: &Board) -> bool {
    board.iter().all(|c| c.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_move_applies() {
        let mut board: Board = Default::default();
        assert!(validate_and_apply(&mut board, Symbol::X, 4, false).is_ok());
        assert_eq!(board[4], Some(Symbol::X));
    }

    #[test]
    fn rejects_out_of_range_cell() {
        let mut board: Board = Default::default();
        assert_eq!(
            validate_and_apply(&mut board, Symbol::X, 9, false),
            Err(MoveError::OutOfRange)
        );
    }

    #[test]
    fn rejects_taken_cell() {
        let mut board: Board = Default::default();
        validate_and_apply(&mut board, Symbol::X, 0, false).unwrap();
        assert_eq!(
            validate_and_apply(&mut board, Symbol::O, 0, false),
            Err(MoveError::CellTaken)
        );
    }

    #[test]
    fn rejects_move_after_game_over() {
        let mut board: Board = Default::default();
        assert_eq!(
            validate_and_apply(&mut board, Symbol::X, 0, true),
            Err(MoveError::GameOver)
        );
    }

    #[test]
    fn detects_row_win() {
        let mut board: Board = Default::default();
        board[0] = Some(Symbol::X);
        board[1] = Some(Symbol::X);
        board[2] = Some(Symbol::X);
        assert_eq!(winner(&board), Some(Symbol::X));
    }

    #[test]
    fn detects_column_win() {
        let mut board: Board = Default::default();
        board[0] = Some(Symbol::O);
        board[3] = Some(Symbol::O);
        board[6] = Some(Symbol::O);
        assert_eq!(winner(&board), Some(Symbol::O));
    }

    #[test]
    fn detects_diagonal_win() {
        let mut board: Board = Default::default();
        board[0] = Some(Symbol::X);
        board[4] = Some(Symbol::X);
        board[8] = Some(Symbol::X);
        assert_eq!(winner(&board), Some(Symbol::X));
    }

    #[test]
    fn no_winner_on_empty_or_mixed_board() {
        let board: Board = Default::default();
        assert_eq!(winner(&board), None);

        let mut mixed: Board = Default::default();
        mixed[0] = Some(Symbol::X);
        mixed[1] = Some(Symbol::O);
        mixed[2] = Some(Symbol::X);
        assert_eq!(winner(&mixed), None);
    }

    #[test]
    fn is_full_detects_draw_board() {
        let mut board: Board = Default::default();
        for (i, cell) in board.iter_mut().enumerate() {
            *cell = Some(if i % 2 == 0 { Symbol::X } else { Symbol::O });
        }
        assert!(is_full(&board));
    }

    #[test]
    fn is_full_false_when_cells_open() {
        let mut board: Board = Default::default();
        board[0] = Some(Symbol::X);
        assert!(!is_full(&board));
    }

    #[test]
    fn other_symbol_toggles() {
        assert_eq!(Symbol::X.other(), Symbol::O);
        assert_eq!(Symbol::O.other(), Symbol::X);
    }
}
